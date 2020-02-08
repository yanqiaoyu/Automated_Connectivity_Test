#获取.cpp文件
SrcFiles=$(wildcard *.c)
#使用替换函数获取.o文件
ObjFiles=$(patsubst %.c,%.o,$(SrcFiles))
#生成的可执行文件
all:main
#目标文件依赖于.o文件
main:$(ObjFiles)
	gcc -o $@ -I ../include $(SrcFiles)
#.o文件依赖于.cpp文件，通配使用，一条就够
%.o:%.cpp
	gcc -c -I ../include $<

.PHONY:clean all

clean:
	rm -f *.o
	rm -f main 

