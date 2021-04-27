# WIP Cryptopals solutions
These are my in-progress Python solutions to the 
[Cryptopals crypto challenges](https://cryptopals.com/). 
So far, I'm up to challenge 15. In addition to learning about cryptography I'm
also doing these as an exercise in test-driven development.

## Missing files
In the public version of this repositiory some files in the `inputs/` directory
are missing because of copyright concerns. This will make a lot of the tests fail.
The missing files are basically 
* encrypted inputs, which can be retrieved from
the Cryptopals website and 
* decrypted solutions, the correct content of which could easily
be figured out by looking at the failing tests in a debugger.

## Tests
Basically, for every solved challenge there is a test in 
`tests/test_challenges.py`. On a lower level of abstraction, there are also unit
tests in the `tests/` directory. I'm using pytest and hypothesis for
property based testing.

## Notes on individual challenges
These are just some minor details I didn't immediately get.

### Challenge 5: Implementing repeating-key xor
Slightly confusing because the intention for linebreaks weren't clear.
The linebreak in the plain text is encrypted. The line break in the 
cypher text is just for decoration and in particular not meant to
indicate the position of the plain text linebreak.
So it must be stripped.

### Challenge 7: AES in ECB mode
This one makes it really important to treat the correct solution as bytes 
rather than text, because with padding that actually makes a difference.

### Challenge 14: Byte-at-a-time ECB decryption (Harder)
This one was harder than it needed to be, because I thought myself into a
corner on challenge 12.

In challenge 12 one way to find the inserted text is now longer than the block
size is to see that the first cyphertext block no longer changes if we change
the byte immediately after the corresponding plaintext block. This doesn't work
for challenge 14, where the insertion point for our text can be in the middle
of a block. A better way is to think about how the size of the cyphertext
changes as plaintext size increases.
