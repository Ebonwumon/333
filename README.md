CMPUT 333 Assignment 1
Group 4: Victoria Bobey, Sarah Morris, Troy Pavlek

Running our files on lab machines:
##Determining Key Length##

python key_length.py [filename] [threshold]

Filename is either ciphertext1 or ciphertext2.
Threshold is a value used to suppress small repetitions in determining key length. Use 10 for cipher1 and 900 for cipher 2.


Question 1:
To find the length of the key, used the file key_length.py. Looking at the distances 
with the largest totals associated with them, we determined all the distances were multipules
of 8.

Question 2:
Used the same file as question 1, but because ciphertext1 was substanially longer, we had to
assume the key was smaller than 200 because the run time was too long. Luckily this showed the key length 
was 33, with all other distances with large totals multiples of 33.

Question 3:
encryption key: group4

