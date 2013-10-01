# Functions to compute potential key length by finding patterns in the ciphertext.
file = open('ciphertext1', 'rb')

# Read the first byte in the file, which is position 0
file_position = 0
byte = file.read(1)
check_byte = {byte} 

# Dictionary to keep track of byte distances 
all_dist = dict()

while True: # Using this because byte != EOF doesnt work in python
    # Check we are not at EOF
    if (len(byte) == 0):
        break
    
    # Check byte has not been looked at already.
    if (byte not in check_byte):
        file.seek(file_position+1)
        cur_byte = file.read(1)
        while True:
            # Check we are not at EOF
            if (len(cur_byte) == 0):
                break 
            # Check if cur_byte matches byte
            if (cur_byte == byte):
                # Calculate distance between positions in file
                distance = (file.tell() - file_position) -1
                # Check if distance is in dictionary, if so increment value
                if (distance in all_dist):
                    all_dist[distance] += 1
                else:
                    all_dist[distance] = 1
            else: pass
            # Move to next byte
            cur_byte = file.read(1)
        byte = file.read(1)
    # If byte has already been checked, move on
    else: pass
    # Increment file position, move to that position, read next byte
    file_position = file_position + 1
    file.seek(file_position)
    byte = file.read(1)

print (all_dist)

"""
Filter results and display anything greater than FILTER_THRESHHOLD
# Results are displayed in an (x,y) format. x is the distance and y is
the number of times this distance occurs throughout the file.
"""
FILTER_THRESHHOLD = 10

Frequent_dists = [(x,y) for x, y in all_dist.items() if y > FILTER_THRESHHOLD]

print ("\nFILTERED RESULTS: (x,y) x is dist between keys & y is frequency")
print (Frequent_dists)

