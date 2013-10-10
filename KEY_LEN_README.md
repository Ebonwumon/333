key_length.py takes two arguements when run through the command line.
Arguement 1 is the file (either ciphertext1 or ciphertext2) and arguement 2 is the
filter threshold.
The way the program find the key length is by looking at the distance between identical bytes in the cipher text and tallying up the distances.
It prints a dictionary initially which shows all the distances and each distances frequency. It is tedious to go through
all the distances, especially in a larger file like ciphertext2.
So filter threshold only shows frequencies equal to or higher than this number.

** For ciphertext1, use 10 as the threshold frequency
** For ciphertext2, use 900. 

Note that ciphertext2 will take about a minute to print because of the size of the file.

The filtered results are printed as tuples (x, y). X represents the distance between identical bytes. Y represents the number of times this occured
in the file.

Key length was determined by looking at the smallest value of x and checking if the majority of the following x are multiples of this number.
For ciphertext1 x1 was 8, x2 was 16, x3 was 24. This was enough proof that the key length was 8.
For ciphertext2 x1 was 33, x2 was 66, x3 was 99. This was enough proof that the key length was 33.
