# Encrypted Data Architecture Plan

## Overview

This document outlines the architectural changes needed to implement end-to-end encryption for Journiv's database and filesystem storage. The goal is to enable shared hosting scenarios where the server administrator cannot access user data, even with direct database or filesystem access.

## Table of Contents

1. [Architecture Overview](#architecture-overview)
2. [Database Encryption](#database-encryption)
3. [Filesystem Encryption](#filesystem-encryption)
4. [Key Management](#key-management)
5. [Search and Indexing](#search-and-indexing)
6. [Migration Strategy](#migration-strategy)
7. [Performance Considerations](#performance-considerations)
8. [Security Considerations](#security-considerations)
9. [Implementation Phases](#implementation-phases)
10. [Edge Cases and Limitations](#edge-cases-and-limitations)

---

## Architecture Overview

### Encryption Scope

**Data to Encrypt:**
- Journal entries (title, content)
- Entry metadata (location, weather)
- Media files (images, videos, audio)
- Media metadata (alt_text, original_filename)
- Tag names
- Journal names and descriptions

**Data NOT Encrypted:**
- User authentication data (passwords are already hashed)
- System metadata (timestamps, IDs, foreign keys)
- Enum values (media_type, upload_status)
- Moods (predefined system data)
- Prompts (predefined system data)

### Encryption Strategy

We will use **client-side encryption** with a user-specific master key:

1. **User Master Key**: Derived from user password using PBKDF2 or Argon2
2. **Data Encryption Keys (DEKs)**: Per-user symmetric keys for encrypting data
3. **Key Encryption Key (KEK)**: Master key encrypts DEKs for storage
4. **Algorithm**: AES-256-GCM for authenticated encryption

```
User Password → Key Derivation (Argon2) → Master Key
Master Key → Encrypts → Data Encryption Key (DEK)
DEK → Encrypts → User Data (entries, media)
```

---

## Database Encryption

### Field-Level Encryption

Implement transparent field-level encryption using SQLAlchemy type decorators:

```python
# New file: app/core/encryption.py

from cryptography.fernet import Fernet
from sqlalchemy.types import TypeDecorator, String, LargeBinary
import base64

class EncryptedString(TypeDecorator):
    """Encrypted string column type."""
    impl = LargeBinary
    cache_ok = True
    
    def __init__(self, key_provider, *args, **kwargs):
        self.key_provider = key_provider
        super().__init__(*args, **kwargs)
    
    def process_bind_param(self, value, dialect):
        """Encrypt value before storing in database."""
        if value is None:
            return None
        key = self.key_provider()
        f = Fernet(key)
        return f.encrypt(value.encode('utf-8'))
    
    def process_result_value(self, value, dialect):
        """Decrypt value when reading from database."""
        if value is None:
            return None
        key = self.key_provider()
        f = Fernet(key)
        return f.decrypt(value).decode('utf-8')
```

### Model Changes

Update models to use encrypted fields:

```python
# app/models/entry.py (modified)

from app.core.encryption import EncryptedString, get_user_encryption_key

class Entry(BaseModel, table=True):
    # Encrypted fields
    title: Optional[str] = Field(
        None,
        sa_column=Column(EncryptedString(get_user_encryption_key), nullable=True)
    )
    content: str = Field(
        ...,
        sa_column=Column(EncryptedString(get_user_encryption_key), nullable=False)
    )
    location: Optional[str] = Field(
        None,
        sa_column=Column(EncryptedString(get_user_encryption_key), nullable=True)
    )
    weather: Optional[str] = Field(
        None,
        sa_column=Column(EncryptedString(get_user_encryption_key), nullable=True)
    )
    # ... rest remains unencrypted (timestamps, IDs, etc.)
```

### Key Storage

Store encrypted DEKs in a new table:

```python
# app/models/user_key.py (new file)

class UserEncryptionKey(BaseModel, table=True):
    """User-specific data encryption keys."""
    __tablename__ = "user_encryption_key"
    
    user_id: uuid.UUID = Field(
        sa_column=Column(
            ForeignKey("user.id", ondelete="CASCADE"),
            nullable=False,
            unique=True
        )
    )
    # DEK encrypted with user's master key (derived from password)
    encrypted_dek: bytes = Field(..., sa_column=Column(LargeBinary, nullable=False))
    # Salt for key derivation
    salt: bytes = Field(..., sa_column=Column(LargeBinary(32), nullable=False))
    # KDF parameters (for Argon2: iterations, memory, parallelism)
    kdf_params: str = Field(..., sa_column=Column(String(500), nullable=False))
    # Key version for key rotation support
    key_version: int = Field(default=1, ge=1)
```

---

## Filesystem Encryption

### File Encryption

Encrypt files before writing to disk:

```python
# app/services/media_service.py (modified)

async def upload_media(
    self,
    file: UploadFile,
    entry_id: uuid.UUID,
    user_id: uuid.UUID,
    session: Session
) -> EntryMedia:
    """Upload and encrypt media file."""
    
    # Read file content
    file_content = await file.read()
    
    # Get user's encryption key
    encryption_key = await self._get_user_encryption_key(user_id, session)
    
    # Encrypt file content
    encrypted_content = self._encrypt_file_content(file_content, encryption_key)
    
    # Generate encrypted filename
    filename = f"{uuid.uuid4()}.enc"
    file_path = self._get_media_path(filename, media_type)
    
    # Write encrypted file
    async with aiofiles.open(file_path, 'wb') as f:
        await f.write(encrypted_content)
    
    # Store encryption metadata
    media = EntryMedia(
        entry_id=entry_id,
        file_path=str(file_path),
        # Store IV and tag for AES-GCM
        encryption_metadata=json.dumps({
            'iv': base64.b64encode(iv).decode(),
            'tag': base64.b64encode(tag).decode(),
            'algorithm': 'AES-256-GCM'
        })
    )
    
    return media
```

### Thumbnail Generation

Generate thumbnails from decrypted content in memory:

```python
async def _generate_thumbnail(
    self,
    file_path: Path,
    user_id: uuid.UUID,
    media_type: MediaType
) -> Optional[bytes]:
    """Generate thumbnail from encrypted file."""
    
    # Decrypt file content in memory
    decrypted_content = await self._decrypt_file(file_path, user_id)
    
    # Generate thumbnail from decrypted bytes
    if media_type == MediaType.IMAGE:
        img = Image.open(BytesIO(decrypted_content))
        img.thumbnail(self.THUMBNAIL_SIZE)
        thumb_bytes = BytesIO()
        img.save(thumb_bytes, format='JPEG')
        return thumb_bytes.getvalue()
    
    # For videos, use ffmpeg with stdin pipe
    # ... similar approach with decrypted content
```

---

## Key Management

### Key Derivation

Derive master key from user password at login:

```python
# app/core/encryption.py

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
import os

def derive_master_key(password: str, salt: bytes) -> bytes:
    """Derive master key from password using PBKDF2."""
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,  # 256 bits
        salt=salt,
        iterations=600000,  # OWASP recommended minimum
    )
    return kdf.derive(password.encode('utf-8'))
```

### Key Lifecycle

1. **Registration**:
   - Generate random salt
   - Derive master key from password
   - Generate random DEK
   - Encrypt DEK with master key
   - Store encrypted DEK and salt

2. **Login**:
   - Retrieve salt from database
   - Derive master key from password
   - Decrypt DEK using master key
   - Store DEK in secure session/memory

3. **Key Rotation**:
   - Generate new DEK
   - Re-encrypt all user data with new DEK
   - Update key_version
   - Background task to avoid timeout

4. **Password Change**:
   - Derive new master key from new password
   - Re-encrypt DEK with new master key
   - DEK itself remains the same (no data re-encryption needed)

### In-Memory Key Storage

Store decrypted keys securely in memory:

```python
# app/core/encryption.py

from contextvars import ContextVar
from typing import Dict
import secrets

# Thread-safe context variable for storing user encryption keys
_user_keys: ContextVar[Dict[str, bytes]] = ContextVar('user_keys', default={})

def set_user_encryption_key(user_id: str, key: bytes) -> None:
    """Store user encryption key in context."""
    keys = _user_keys.get().copy()
    keys[user_id] = key
    _user_keys.set(keys)

def get_user_encryption_key(user_id: str) -> Optional[bytes]:
    """Retrieve user encryption key from context."""
    return _user_keys.get().get(user_id)

def clear_user_encryption_key(user_id: str) -> None:
    """Clear user encryption key from context."""
    keys = _user_keys.get().copy()
    keys.pop(user_id, None)
    _user_keys.set(keys)
```

### Middleware for Key Management

```python
# app/middleware/encryption_middleware.py

from fastapi import Request
from app.core.encryption import set_user_encryption_key, load_user_dek

async def encryption_middleware(request: Request, call_next):
    """Load user encryption key for authenticated requests."""
    
    # Get current user from JWT token
    user = await get_current_user(request)
    
    if user:
        # Load and decrypt user's DEK
        # Master key should be stored in secure session
        master_key = request.session.get('master_key')
        if master_key:
            dek = load_user_dek(user.id, master_key)
            set_user_encryption_key(str(user.id), dek)
    
    response = await call_next(request)
    
    # Clear key after request
    if user:
        clear_user_encryption_key(str(user.id))
    
    return response
```

---

## Search and Indexing

### Challenge

Encrypted data cannot be searched directly. We need alternative approaches:

### Solution 1: Client-Side Search (Most Secure)

- Fetch encrypted data to client
- Decrypt in browser
- Search in memory
- **Pros**: Maximum security, no server-side index
- **Cons**: Slow for large datasets, high bandwidth

### Solution 2: Searchable Encryption (Recommended)

Use deterministic encryption for search terms:

```python
# app/core/encryption.py

def create_search_token(term: str, user_dek: bytes) -> str:
    """Create deterministic search token."""
    # Use HMAC for deterministic but secure tokens
    h = hmac.new(user_dek, term.lower().encode(), hashlib.sha256)
    return h.hexdigest()
```

Store search tokens in separate table:

```python
# app/models/entry_search_index.py

class EntrySearchIndex(BaseModel, table=True):
    """Search index for encrypted entries."""
    __tablename__ = "entry_search_index"
    
    entry_id: uuid.UUID = Field(foreign_key="entry.id", ondelete="CASCADE")
    user_id: uuid.UUID = Field(foreign_key="user.id", ondelete="CASCADE")
    # Deterministic tokens for each word
    search_token: str = Field(..., max_length=64, index=True)
    # Encrypted position information
    encrypted_context: Optional[bytes] = Field(None)
    
    __table_args__ = (
        Index('idx_search_token_user', 'search_token', 'user_id'),
    )
```

Search workflow:
1. User searches for "birthday party"
2. Generate tokens: `[token("birthday"), token("party")]`
3. Query: `SELECT entry_id WHERE search_token IN (tokens) AND user_id = current_user`
4. Decrypt matched entries on client/server
5. Highlight matches

### Solution 3: Hybrid Approach

- Store encrypted full text
- Store encrypted keywords separately
- Use bloom filters for fast negative lookups
- Decrypt only potential matches

---

## Migration Strategy

### Phase 1: Add Encryption Support (No Breaking Changes)

1. Add encryption module and configuration
2. Add `UserEncryptionKey` table
3. Add optional encryption to models (backward compatible)
4. Add feature flag: `ENCRYPTION_ENABLED=false`

### Phase 2: Enable for New Users

1. Generate keys for new user registrations
2. Encrypt new data automatically
3. Existing users remain unencrypted
4. Add UI: "Enable Encryption" button for existing users

### Phase 3: Data Migration

Provide migration tool for existing users:

```python
# scripts/migrate_to_encryption.py

async def migrate_user_data(user_id: uuid.UUID, password: str):
    """Migrate existing user data to encrypted format."""
    
    # Generate encryption keys
    salt = os.urandom(32)
    master_key = derive_master_key(password, salt)
    dek = Fernet.generate_key()
    encrypted_dek = encrypt_with_key(dek, master_key)
    
    # Store key
    user_key = UserEncryptionKey(
        user_id=user_id,
        encrypted_dek=encrypted_dek,
        salt=salt,
        kdf_params=json.dumps({'iterations': 600000})
    )
    session.add(user_key)
    
    # Encrypt all entries
    entries = session.exec(
        select(Entry).where(Entry.user_id == user_id)
    ).all()
    
    for entry in entries:
        entry.content = encrypt_field(entry.content, dek)
        entry.title = encrypt_field(entry.title, dek)
        # ... encrypt other fields
        session.add(entry)
    
    # Encrypt all media files
    media_files = session.exec(
        select(EntryMedia)
        .join(Entry)
        .where(Entry.user_id == user_id)
    ).all()
    
    for media in media_files:
        await encrypt_media_file(media, dek)
        session.add(media)
    
    session.commit()
```

### Rollback Strategy

- Keep unencrypted backups before migration
- Add `encryption_status` field to track migration state
- Support mixed encrypted/unencrypted data during transition

---

## Performance Considerations

### Encryption Overhead

- **CPU**: AES-256-GCM is hardware-accelerated on most CPUs (AES-NI)
- **Overhead**: ~5-10% for small data, <1% for large files
- **Memory**: DEKs are small (32 bytes), minimal overhead

### Optimization Strategies

1. **Batch Operations**: Encrypt/decrypt multiple records together
2. **Connection Pooling**: Reuse encryption contexts
3. **Caching**: Cache decrypted data temporarily (with TTL)
4. **Streaming**: Use streaming encryption for large files
5. **Parallel Processing**: Use asyncio for concurrent operations

### Benchmarks

Expected performance impact:
- Entry creation: +10-20ms
- Entry retrieval: +5-10ms
- Media upload: +50-100ms (depends on file size)
- Search: +50-200ms (with searchable encryption)

---

## Security Considerations

### Threat Model

**Protected Against:**
- Database administrator reading user data
- Filesystem administrator reading media files
- Stolen database backups
- Server compromise (if keys are in memory only during request)

**NOT Protected Against:**
- Compromised user password
- Memory dumps during active session
- Server-side code injection
- Keylogger on user's device
- Man-in-the-middle attacks (requires HTTPS)

### Best Practices

1. **HTTPS Required**: Encryption is useless without TLS
2. **Key Rotation**: Support periodic key rotation
3. **Audit Logging**: Log all key access (without exposing keys)
4. **Rate Limiting**: Prevent brute force on encrypted data
5. **Secure Key Storage**: Never log or expose keys
6. **Memory Protection**: Use secure memory for keys (mlocked pages)
7. **Zero-Knowledge**: Server should never see plaintext passwords

### Authentication Changes

User authentication must derive the master key:

```python
# app/api/v1/endpoints/auth.py (modified)

async def login(credentials: LoginRequest):
    # Verify password hash as usual
    user = authenticate_user(credentials.username, credentials.password)
    
    # Derive master key from password
    user_key_record = get_user_encryption_key_record(user.id)
    if user_key_record:
        master_key = derive_master_key(
            credentials.password,
            user_key_record.salt
        )
        # Decrypt DEK
        dek = decrypt_dek(user_key_record.encrypted_dek, master_key)
        
        # Store in secure session (encrypted session cookie)
        session['encryption_key'] = base64.b64encode(dek).decode()
    
    return access_token
```

---

## Implementation Phases

### Phase 1: Foundation (2-3 weeks)

- [ ] Add cryptography dependencies
- [ ] Implement encryption core module
- [ ] Add `UserEncryptionKey` model and migration
- [ ] Add configuration flags
- [ ] Write unit tests for encryption/decryption
- [ ] Update security documentation

### Phase 2: Database Encryption (3-4 weeks)

- [ ] Implement encrypted column types
- [ ] Update Entry model with encrypted fields
- [ ] Update EntryMedia model with encrypted fields
- [ ] Add key management to authentication flow
- [ ] Implement encryption middleware
- [ ] Add integration tests
- [ ] Test with SQLite and PostgreSQL

### Phase 3: Filesystem Encryption (2-3 weeks)

- [ ] Implement file encryption in MediaService
- [ ] Update thumbnail generation for encrypted files
- [ ] Update file serving with decryption
- [ ] Add encryption metadata to EntryMedia
- [ ] Test with various media types
- [ ] Performance testing and optimization

### Phase 4: Search Support (3-4 weeks)

- [ ] Implement searchable encryption
- [ ] Create EntrySearchIndex model
- [ ] Update search service
- [ ] Add search token generation
- [ ] Update search UI
- [ ] Test search performance

### Phase 5: Migration Tools (2 weeks)

- [ ] Create migration script
- [ ] Add user-facing migration UI
- [ ] Implement rollback mechanism
- [ ] Add progress tracking
- [ ] Test migration with large datasets

### Phase 6: Production Hardening (2 weeks)

- [ ] Security audit
- [ ] Performance optimization
- [ ] Documentation
- [ ] User guide for encryption
- [ ] Backup and recovery procedures
- [ ] Monitor error rates and performance

**Total Estimated Time: 14-18 weeks**

---

## Edge Cases and Limitations

### Edge Cases to Handle

1. **Password Reset**:
   - Problem: Lost password means lost encryption key
   - Solution: Add recovery keys or backup encryption with recovery email
   - Trade-off: Reduces security guarantee

2. **Shared Entries** (future feature):
   - Problem: How to share encrypted entry with another user
   - Solution: Encrypt with recipient's public key (asymmetric encryption)
   - Requires: Public/private key pairs per user

3. **Export/Import**:
   - Problem: Encrypted exports are still encrypted
   - Solution: Decrypt during export, re-encrypt on import
   - Option: Export with password protection

4. **Full-Text Search**:
   - Problem: Cannot use database full-text search on encrypted data
   - Solution: Client-side search or searchable encryption
   - Trade-off: Performance impact

5. **Analytics**:
   - Problem: Server-side analytics need access to content
   - Solution: Generate analytics client-side or use aggregates only
   - Limitation: Word frequency, content analysis won't work

6. **Memory Constraints**:
   - Problem: Decrypting large datasets can consume memory
   - Solution: Stream decryption, pagination
   - Limitation: Some operations may be slower

7. **Multi-Device Sync**:
   - Problem: Each device needs the encryption key
   - Solution: Derive key on each device from password
   - Requirement: User must enter password on each device

8. **Background Tasks**:
   - Problem: Celery workers don't have user's encryption key
   - Solution: Pass encrypted DEK with task, decrypt in worker
   - Risk: Key exposure in task queue (mitigate with encrypted queue)

### Known Limitations

1. **Search Performance**: Searchable encryption is slower than plaintext search
2. **Server-Side Analytics**: Limited without access to plaintext
3. **Password Recovery**: Forgot password = lost data (unless recovery key)
4. **Migration Time**: Large datasets take time to encrypt
5. **Backward Compatibility**: Encrypted data format changes are breaking
6. **Development Complexity**: Encryption adds code complexity and debugging difficulty

### Future Enhancements

1. **Asymmetric Encryption**: Support for sharing between users
2. **Key Escrow**: Optional encrypted backup of keys
3. **Hardware Security Modules**: For enterprise deployments
4. **Homomorphic Encryption**: For server-side analytics (research stage)
5. **Zero-Knowledge Proof**: Verify data integrity without decryption

---

## Configuration

### Environment Variables

```bash
# Enable encryption (default: false for backward compatibility)
ENCRYPTION_ENABLED=true

# Encryption algorithm (default: AES-256-GCM)
ENCRYPTION_ALGORITHM=aes-256-gcm

# Key derivation iterations (default: 600000)
ENCRYPTION_KDF_ITERATIONS=600000

# Enable searchable encryption (default: true if encryption enabled)
ENCRYPTION_SEARCHABLE=true

# Session timeout for encryption keys (default: 15 minutes)
ENCRYPTION_KEY_TIMEOUT=900

# Require re-authentication for sensitive operations (default: true)
ENCRYPTION_REQUIRE_REAUTH=true
```

### Feature Flags

```python
# app/core/config.py (additions)

class Settings(BaseSettings):
    # Encryption Configuration
    encryption_enabled: bool = False
    encryption_algorithm: str = "aes-256-gcm"
    encryption_kdf_iterations: int = 600000
    encryption_searchable: bool = True
    encryption_key_timeout: int = 900  # seconds
    encryption_require_reauth: bool = True
```

---

## Testing Strategy

### Unit Tests

```python
# tests/unit/test_encryption.py

def test_encrypt_decrypt_string():
    """Test string encryption and decryption."""
    key = Fernet.generate_key()
    plaintext = "Secret journal entry"
    ciphertext = encrypt_string(plaintext, key)
    decrypted = decrypt_string(ciphertext, key)
    assert decrypted == plaintext
    assert ciphertext != plaintext

def test_key_derivation():
    """Test key derivation from password."""
    password = "user_password123"
    salt = os.urandom(32)
    key1 = derive_master_key(password, salt)
    key2 = derive_master_key(password, salt)
    assert key1 == key2  # Same password and salt = same key
    
    key3 = derive_master_key(password, os.urandom(32))
    assert key1 != key3  # Different salt = different key
```

### Integration Tests

```python
# tests/integration/test_encrypted_entries.py

async def test_create_encrypted_entry(client, encrypted_user):
    """Test creating entry with encryption enabled."""
    response = await client.post(
        "/api/v1/entries",
        json={"content": "My secret thoughts", "journal_id": journal_id},
        headers={"Authorization": f"Bearer {token}"}
    )
    assert response.status_code == 201
    
    # Verify data is encrypted in database
    entry = db.get(Entry, response.json()["id"])
    assert entry.content != "My secret thoughts"  # Should be encrypted
    assert isinstance(entry.content, bytes)  # Encrypted is binary
```

### Security Tests

```python
# tests/security/test_encryption_security.py

def test_different_users_different_keys():
    """Ensure different users have different encryption keys."""
    user1_key = get_user_encryption_key(user1_id)
    user2_key = get_user_encryption_key(user2_id)
    assert user1_key != user2_key

def test_key_not_logged():
    """Ensure encryption keys are never logged."""
    with capture_logs() as logs:
        key = derive_master_key("password", salt)
        assert key.hex() not in logs
```

---

## Conclusion

Implementing end-to-end encryption for Journiv is a significant undertaking that requires careful planning and execution. This plan provides a roadmap for:

1. **Zero-knowledge architecture**: Server cannot read user data
2. **Backward compatibility**: Gradual rollout without breaking existing users
3. **Performance**: Minimal impact on user experience
4. **Security**: Industry-standard cryptography with proper key management
5. **Usability**: Transparent to users except for initial setup

The phased approach allows for:
- Early feedback on design decisions
- Risk mitigation through incremental changes
- Testing at each stage
- Option to pause or adjust based on results

**Key Success Factors:**
- Strong cryptography (AES-256-GCM, Argon2)
- Secure key management (never store master keys)
- Transparent operation (encryption happens automatically)
- Good UX (password prompt only when necessary)
- Comprehensive testing (unit, integration, security)

**Trade-offs to Accept:**
- Slower search performance
- Limited server-side analytics
- No password recovery without data loss (unless recovery keys)
- Increased code complexity

This plan prioritizes **security and privacy** while maintaining **usability and performance**. The implementation can be adjusted based on user feedback and real-world usage patterns.

---

## References

- [OWASP Cryptographic Storage Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Cryptographic_Storage_Cheat_Sheet.html)
- [Cryptography Library Documentation](https://cryptography.io/)
- [Searchable Encryption Research](https://eprint.iacr.org/2000/034.pdf)
- [Key Management Best Practices (NIST)](https://csrc.nist.gov/publications/detail/sp/800-57-part-1/rev-5/final)
- [Field-Level Encryption in Applications](https://www.mongodb.com/docs/manual/core/security-client-side-encryption/)
