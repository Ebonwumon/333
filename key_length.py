# Functions to compute potential key length by finding patterns in the ciphertext.
file = open('ciphertext1', 'r')

# Read the first byte in the file, which is position 0
byte = file.read(1)
check_byte = {byte} 
file_position = 0

# Dictionary to keep track of byte distances 
all_dist = dict()

while (byte != EOF):
    # Check this byte has not already been looked at
    if (byte not in check_byte):
        file.seek(file_position+1)
        cur_byte = file.read(1)
        while (cur_byte != EOF):
            #Check if cur_byte matches byte
            if (cur_byte == byte):
                #Calculate distance between bytes
                distance = ( file.tell() - file_position)
                #Check if distance is in dictonary, if so increment
                if (distance in all_dist):
                    all_dist[distance] += 1
                else:
                    all_dist[distance] = 1
            else: pass
            cur_byte = file.read(1)
        byte = file.read(1)
    # If byte has already been checked, move to the next one
    else:
        file.seek(file_position+1)
        byte = file.read(1)
    # Increment to the next byte
    file_position = file_postion + 1

print all_dist

