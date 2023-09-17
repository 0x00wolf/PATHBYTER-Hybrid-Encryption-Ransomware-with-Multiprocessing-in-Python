file_bytesize = 512 * 1024
message = "hello world"
for i in range(100000)
    with open('test.txt', 'w') as f:
        repeat_amount = int((file_bytesize/len(message)))
        f.write(message*repeat_amount)
