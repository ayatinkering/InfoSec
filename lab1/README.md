# Lab 1: Basic Symmetric Key Ciphers

All six regular manual exercises. Additional questions are excluded.
Adapted from [your existing lab code](https://github.com/ayatinkering/ayati-all-labs/tree/main/lab1%20Symetric), preserving its simple loops and function structure.

## Run in PyCharm

Open any question file and Run. Enter your own message/key, or press Enter
at each prompt to use the manual values shown. Python standard library only:
no package installation required.

Run `run_all.py` to execute all nine scripts (covering Q1-Q6) with manual defaults.
From the project root: `python lab1/run_all.py` (or `python3`).

## Find the code you need

| Question | File | Reusable functions |
| --- | --- | --- |
| Q1(a) | `q1_additive.py` | `encrypt(s, k)`, `decrypt(s, k)` |
| Q1(b) | `q1_multiplicative.py` | `encrypt(s, k)`, `decrypt(s, k)`, `mod_inv(a, m)` |
| Q1(c) | `q1_affine.py` | `encrypt(s, a, b)`, `decrypt(s, a, b)` |
| Q2(a) | `q2_vigenere.py` | `encrypt(s, k)`, `decrypt(s, k)` |
| Q2(b) | `q2_autokey.py` | `encrypt(s, k)`, `decrypt(s, k)` |
| Q3 | `q3_playfair.py` | `make_matrix(k)`, `prepare(s)`, `encrypt(s, m)`, `decrypt(s, m)` |
| Q4 | `q4_hill.py` | `encrypt(s, k)`, `decrypt(s, k)`, `inv_matrix(k)` |
| Q5 | `q5_known_plaintext_attack.py` | `find_key(p, c)`, `decrypt(s, k)` |
| Q6 | `q6_affine_brute_force.py` | `find_keys(p, c)`, `decrypt(s, a, b)` |

Every question file is self-contained: all its functions are in that file.
`main()` contains only the input/output demonstration. Importing a file does
not prompt for input or execute the demo.

## Adapt to a new exam question

1. Pick the cipher file and copy its functions into your new program, or import
   the module when your new program is in the same folder.
2. Pass the new message and key to `encrypt()`; keep the returned ciphertext.
3. Pass that ciphertext and key to `decrypt()` to check recovery.
4. Connect those returned values to the other operations the question requests.

For example, in a new file beside the question files:

```python
import q1_affine as affine
import q2_vigenere as vigenere

message = "NEW EXAM MESSAGE"
first = affine.encrypt(message, 5, 8)
second = vigenere.encrypt(first, "SECRET")

# Undo composed operations in reverse order.
first_again = vigenere.decrypt(second, "SECRET")
original = affine.decrypt(first_again, 5, 8)
print(second)
print(original)
```

No shared `ciphers.py` is required. Names such as `s`, `k`, `p`, `c` follow your
reference: string, key, plaintext, ciphertext. `ans` accumulates the result.

## Conventions and small corrections to the reference

- A=0 through Z=25. Classical ciphers here normalize English letters to uppercase
  and remove spaces/punctuation. Q5's decrypt preserves punctuation as in the reference.
- Invalid multiplicative keys, empty Vigenere keywords, inconsistent known pairs,
  and incomplete ciphertext pairs produce clear errors.
- Playfair merges J into I and retains inserted fillers after decryption. Filler
  is X normally, Q when separating/padding X itself, to avoid an XX pair.
- Hill uses a 2x2 matrix, column vectors, and X padding on encryption. Decryption
  retains padding and does not silently pad malformed ciphertext.
- Q5 literally recovers TREASUSE from XVIEWYWI with key 4. This apparent manual
  typo is reported; the input is not changed to force TREASURE.
- Q6 tries all 312 valid affine keys against AB -> GL, finding (5,6). Its literal
  plaintext is THEBESTOFAFIGHTISMAKINGUPAKTERWARDS; AKTERWARDS is an apparent typo.

These classical ciphers are educational, not suitable for protecting real data.
