# Block Cipher Questions and Answers

### Question 1

**If AES-256 is the underlying block cipher and if the nonce is 118-bit long, what is the maximal size a plaintext can have? Justify.**

The maximal size a plaintext can have is determined by the number of blocks we can cipher. With a 128-bit block size and a 118-bit nonce, we are left with 10 bits for the counter. Thus, we have 2<sup>10</sup> maximum possible blocks. Since each block is 128 bits (16 bytes), the maximal size is 16 * 2<sup>10</sup> bytes, which equals 16 KB.

### Question 2

**We decide to use a nonce of 8 bits (still with AES-256). Which new constraint do we have in our system? Be as precise as possible. In particular, this constraint might be different based on the way we choose the nonce.**

If we have a determined nonce, we are not allowed to use the same nonce twice. However, if we are using a random nonce, we need to apply the birthday paradox to keep it secure. This means that we have to apply the formula below to ensure security:

$$1 - e^{-n^2/(2d)}$$

The probability to break the algorithm can be calculated using this formula, where:
- \( n \) is the number of possible nonces.
- \( d \) is the total number of blocks that can be encrypted securely.

### Question 3

**A bank comes to you and wants some help with CTR. They are using 3 key 3-DES (key size: 168 bits, block size 64 bits). Here is their usage scenario:**
- **Changing 3-DES is not an option.**
- **All transactions are sent using the same key.**
- **They send 2<sup>30</sup> transactions per year.**
- **A transaction is at most 2<sup>26</sup> bits long.**
- **The symmetric key is changed every year.**

**They are wondering what nonce size they should use. What do you tell them? Justify.**