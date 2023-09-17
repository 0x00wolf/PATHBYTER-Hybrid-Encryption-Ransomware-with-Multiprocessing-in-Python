file_bytesize = 512 * 1024
message = "You wanted to know who I am, Zero Cool? Well, let me explain the New World Order. Governments and corporations need people like you and me. We are Samurai... the Keyboard Cowboys... and all those other people who have no idea what's going on are the cattle... Moooo. "
x = 0
y = 100000
while x < y:
    x += 1
    with open(f'helloworld{x}.txt', 'w') as f:
        repeat_amount = int((file_bytesize/len(message)))
        f.write(message*repeat_amount)
