"""
f = open("text.txt")
f = open(r"h:\test\text.txt", 'r')
print(r"h:\test\text.txt")

my = ("progit.pdf", "rb")
while True:
    content = my.read(1024)
    print(content)
    if not content:
    break
f = open("text.txt", "w")
str_list = ['stroka1 stroka2 stroka3\n', 'Hello world']
f.writelines(str_list)

with open("text.txt") as f:
    for line in f:
        print(line)

f = open("text.txt", "r")
for line in f:
    print(line)
f.close()

with open("text.txt", "w") as f:
str_list = ['stroka1 stroka2 stroka3\n', 'Hello world']
for str_list in f:
f.writelines(str_list)


try:
    f_obj = open("text.txt", "r")
    for line in f_obj:
        print(line)
except IOError:
    print("Произошла ошибка ввода-вывода!")
finally:
    f_obj.close()



f = open("text.txt", "+w")
f.write("my_var")
f.seek(0)
content = f.read()
print(content)

f_obj = open("new_f.txt", "w")
print("Файл. Имя: ", f_obj.name)
print("Файл. Закрыт: ", f_obj.closed)
print("Файл. Режим: ", f_obj.mode)

f_obj = open("new_f.txt")
print(f_obj.read(3))
print("Мы находимся на позиции: ", f_obj.tell())
# Перемещаемся в начало
f_obj.seek(0)
print(f_obj.read(3))
f_obj.close()

with open("text.yaml", "w") as f:
    print("Hello, I'm from Russia", file=f)

import os

print(os.path.join("h:/habr/", "lesson4.py"))

import json

with open("test.json", "w") as f:
    json.dump('data', f)
"""
a = [1, 2, 3, 4, 5]
print(a[0:3:-1])
