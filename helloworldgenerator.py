file_bytesize = 512 * 1024
message = "hello world"
start = 0
finish = 11010
while start < finish:
    with open('test.txt', 'w') as f:
        repeat_amount = int((file_bytesize/len(message)))
        f.write(message*repeat_amount)
    start += 1
