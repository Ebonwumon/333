CMPUT 333 Assignment 1
Group 4: Victoria Bobey, Sarah Morris, Troy Pavlek

Running our files on lab machines:
##Determining Key Length##

python key_length.py [filename] [threshold]

Filename is either ciphertext1 or ciphertext2.
Threshold is a value used to suppress small repetitions in determining key length. Use 10 for cipher1 and 900 for cipher 2.

##Cipher 1##
Once you have the key length, you can run the files. For Cipher1 run:

php cipher1.php [key length]

The key length you will have gotten from the previous program. For cipher 1, it is 8.

The program will determine three potential keys for the file. You may use the onscreen prompts to select one, and then it will display the decryption with that key. The correct key is 2brodsky

##Cipher 2##
Run:

php cipher2.php [key length]

The key length for this file is 33.

The program will then present you with all the potential characters for the next five slots in the key. It is your job, as a human to determine which leads to a readable, sensible and understandable string. I believe in you, there are only a few options per slot. You must input it one character at a time, separated by the return key. The correct key is Large_Hadron_Collider_at_CERN_map.

After the program returns "DONE!" you can open decrypted.pdf from the folder with your favourite PDF reader to view the map.

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

