### Environments
Ubuntu 16.04, g++-7.5.0, cmake-3.13.0, g++-7.5.0

### How to run
+ Go to either `3.2.0` or `3.5.6` directories, this refers to the version
  number of SEAL
+ Run `cmake .`
+ `make`
+ `./expand`

### What this example is about
+ I tried to use the `expand_query` function in sealPIR, in the main program, I
generated a plaintext of `"Ax^1"`, then encrypt it and ran `expand_query` on
this ciphertext. 

+ For simplicity, here I only expanded this into `4` ciphertexts instead of the
number of poly modulus. Then I decrypted the ciphertexts to see the results.
Correct output should be `0, 40, 0, 0`.

+ I repeated the procedures above for twice in the main function as a for loop.

### Issues encountered
+ In SEAL 3.2.0, every time I will get the correct output, however, when the
  program exited, and I believe that is when the memorypool started cleaning up
  everyting, it showed a segmentation fault bug.

+ In SEAL 3.5.6, for the first run, the expansion will get the correct output,
  but for the second run, results will become incorrect. I decrypted some
  ciphertexts during the execution of `expand_query` to see where the ciphertext
  goes wrong. And it turns out that at `line 131`, we executed
  `multiply_power_of_X(temp[a], tempctxt_shifted, index_raw, params);`, but
  `newtemp[a]` changes after that execution, although I believe this function
  has no impact on `newtemp[a]`. 
  
  You can check that this by seeing the output when running `expand`. 

  You should see something similar to this during the second run:

  `0 (c0 + sub) to string: 0`

  `0 after mul new temp: 3093AEE8x^8191 + 3D45D00Bx^8190 + 2A634A1x^8189 +
  3CE3777Fx^8188 + 2463A898x^8187 + 1C662308x^8186...` 

  These two are the output of `line 127` and `line 137` where we output the
  plaintext after decrypting `newtemp[a]`.

### Some guess about this
+ This might be related to the `memorypool` part, since it seems to have some
  memory corruptions?