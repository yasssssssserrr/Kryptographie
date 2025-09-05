 # Hybrid File Crypto (RSA + AES/CTR) in Java

> Gradle project implementing a **hybrid cryptosystem**:
> - **RSA** protects the per-file **AES session key** (key encapsulation)
> - **AES/CTR/NoPadding** encrypts the **file payload**
> - **SHA512withRSA** signs the **AES key** for authenticity

Modules:
- `RSAKeyCreation.java` — generate RSA keypair and write `<owner>.pub` / `<owner>.prv`
- `SSF.java` — **S**ign & **S**ymmetric-encrypt to `.ssf` container
- `RSF.java` — **R**SA **S**ecure **F**ile: decrypt `.ssf`, verify signature, write plaintext
- `Utils.java` — small helpers (hex printing, IO, error handling)

---

## File formats

### Key files (`<owner>.pub` / `<owner>.prv`)
Written by `RSAKeyCreation`:

1. `int` — length of owner name  
2. `byte[]` — owner name (UTF-8)  
3. `int` — length of key bytes  
4. `byte[]` — key bytes  
   - public key bytes are **X.509** encoded  
   - private key bytes are **PKCS#8** encoded

> Both `RSF` and `SSF` read keys with `KeyFactory("RSA")` using **X509EncodedKeySpec** (public) and **PKCS8EncodedKeySpec** (private).

### Encrypted container (`.ssf`)
Written by `SSF.writeEncryptedFile(...)` and read by `RSF.readAndDecryptFile()` in this order:

1. `int` + `byte[]` — **RSA-encrypted AES key**  
2. `int` + `byte[]` — **SHA512withRSA signature** of the **raw AES key bytes**  
3. `int` + `byte[]` — **AES parameters** (`AlgorithmParameters` bytes for `AES/CTR`)  
4. `byte...` — **AES/CTR/NoPadding** ciphertext of the input file (streamed; final block via `doFinal()`)

## Build

This is a **Gradle** project.

```bash
# compile & run tests
./gradlew clean build

# (no application plugin) — run classes manually:
#   SSF:  java -cp build/classes/java/main Praktikum3.SSF <sender> <receiver> <plainFile> <encryptedFile>
#   RSF:  java -cp build/classes/java/main Praktikum3.RSF <sender> <receiver> <encryptedFile> <outputFile>
```
> IDE: Import as Gradle project (IntelliJ/Eclipse/VS Code). Run the main methods in Praktikum3.SSF and Praktikum3.RSF.

## Usage
1) Generate keys: Generates <owner>.pub (X.509) and <owner>.prv (PKCS#8) in the working directory
>
```java -cp build/classes/java/main Praktikum3.RSAKeyCreation Alice ```
>
```java -cp build/classes/java/main Praktikum3.RSAKeyCreation Bob```
>
2) Encrypt & sign (SSF): SSF <sender> <receiver> <plainFile> <encryptedFile>
``` java -cp build/classes/java/main Praktikum3.SSF Alice Bob ./data/input.bin ./data/message.ssf ```
>
3) Decrypt & verify (RSF): RSF <sender> <receiver> <encryptedFile> <outputFile>
>
```java -cp build/classes/java/main Praktikum3.RSF Alice Bob ./data/message.ssf ./data/output.bin ```
>
Where are the keys read from?
>
Both SSF and RSF call setFileKey(s) with a directory prefix + base name to load <name>.pub and <name>.prv.
>
## Implementation notes
Ciphers used:
- Cipher.getInstance("RSA") for key encapsulation (provider default padding, typically PKCS#1 v1.5)
- Cipher.getInstance("AES/CTR/NoPadding") for streaming file encryption/decryption
- Signature: Signature.getInstance("SHA512withRSA") signs AES key bytes; verified on decrypt
- Streaming: file I/O uses Cipher.update(...) in a loop, flushes tail via doFinal()
- Buffer size: constructors have overloads with and without bufferSize (default internal)
