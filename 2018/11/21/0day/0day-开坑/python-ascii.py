#-*- coding -*-
#python3
import re

def ascii_to_str():
	# 输入字符，两个数字
	input_str = "40 FF 19 00 EB 10 40 00"
	li = input_str.split(" ")
	result_str = ''
	for i in li:
		result_str += str(chr(int(i)))
	print("ascii is : {}".format(result_str))
	return result_str
	
ascii_to_str()
	

