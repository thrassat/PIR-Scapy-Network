def init():
	global nmbStandard 
	global minFreqSyn
	global maxFreqSyn
	global nmbStandardFTP
	global minFreqFTP
	global maxFreqFTP
	nmbStandard = 0
	minFreqSyn = 0
	maxFreqSyn = 0
	nmbStandardFTP = 0
	minFreqFTP = 0
	maxFreqFTP = 0

def write():
	with open('comm', 'w+') as the_file:
		the_file.write(str(nmbStandard)+"\n")
		the_file.write(str(minFreqSyn)+"\n")
		the_file.write(str(maxFreqSyn)+"\n")
		the_file.write(str(nmbStandardFTP)+"\n")
		the_file.write(str(minFreqFTP)+"\n")
		the_file.write(str(maxFreqFTP)+"\n")

def getParameters():
	with open('comm') as f:
		lines = [x.rstrip('\n') for x in f.readlines()]
	
	res = []
	for line in lines:
		res.append(line)

	return res

def main():
	init()
	write()
	print(getParameters())

if __name__=='__main__':
	main()
