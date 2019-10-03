from idc      import *
from idaapi   import *
from idautils import *


possibleChars = list("abcdefghijklmnopqrstuvwxyz0123456789_ABCDEFGHIJKLMNOPQRSTUVWXYZ")
possible2 = list("ABCD")
#possible5 = list("ABCDEFGHIJKLMNOP")
possible5 = list("AB")
possible6 = list("EFGH")
possible7 = list("ST")
possible8 = list("X")
#possible9 = list("ghijklmnopqrstuv")
possible9 = list("m")
#possible10 = list("EFGH")
possible10 = list("EF")

possible26 = list("klmn")


ii = [0] * 32
totalCount = 0
inputAddr = 0
resultAddr = 0
done = 0


class MyDbgHook(DBG_Hooks):
	def dbg_bpt(self, tid, ea):
		#print "Break point at 0x%x pid=%d" % (ea, tid)
		global possibleChars, possible26, inputAddr, resultAddr, done, ii, totalCount

		if done == 0 :
			RefreshDebuggerMemory()


			rr = [0] * 32
			for i in range(0, 32) :
				rr[i] = Byte(resultAddr + i)

			if rr[0] == 0x70 and rr[1] == 0x70 and rr[2] == 0xB2 and rr[3] == 0xAC and rr[4] == 1 and rr[5] == 0xD2 and rr[6] == 0x5E and rr[7] == 0x61 and rr[8] == 0x0A and rr[9] == 0xA7 and rr[10] == 0x2A and rr[11] == 0xA8 and rr[12] == 0x8 and rr[13] == 0x1C and rr[14] == 0x86 and rr[15] == 0x1A and rr[16] == 0xE8 and rr[17] == 0x45 and rr[18] == 0xC8 and rr[19] == 0x29 and rr[20] == 0xB2 and rr[21] == 0xF3 and rr[22] == 0xA1 and rr[23] == 0x1E :
				cc = [0] * 32
				for i in range(0, 32) :
					cc[i] = Byte(inputAddr + i)

				print "Found Match: ", [chr(ce) for ce in cc], " Index: ", ii, " :: Res: ", [hex(x) for x in rr]
				done = 0



			'''ii[9] += 1
			if ii[9] == len(possible9) :
				ii[9] = 0
				ii[10] += 1
				if ii[10] == len(possible10) :
					ii[10] = 0
					ii[11] += 1
					if ii[11] == len(possibleChars) :
						ii[11] = 0
						print "DONE!", totalCount
						done = 1
			PatchByte(inputAddr + 9, ord(possible9[ ii[9] ]))
			PatchByte(inputAddr + 10, ord(possible10[ ii[10] ]))
			PatchByte(inputAddr + 11, ord(possibleChars[ ii[11] ]))'''

			ii[30] += 1
			if ii[30] == len(possibleChars) :
				ii[30] = 0
				#print "Index:", ii, " VAL:", [hex(x) for x in rr], " T:", totalCount
				ii[31] += 1
				if ii[31] == len(possibleChars) :
					ii[30] = 0
					print "DONE!", totalCount
					done = 1
			PatchByte(inputAddr + 30, ord(possibleChars[ ii[30] ]))
			PatchByte(inputAddr + 31, ord(possibleChars[ ii[31] ]))


			# Show how each byte is affected by a particular offset
			'''offset = 21
			inputOffset = 25
			ii[offset] += 1
			if ii[offset] == len(possibleChars) :
				ii[offset] = 0
				print "DONE!", inputOffset
				done = 1
			PatchByte(inputAddr + inputOffset, ord(possibleChars[ ii[offset] ]))
			print "Will try:", ii[offset], " VAL: ", [hex(x) for x in rr]'''


			#print "Will try:", ii, " VAL: ", [hex(x) for x in rr]

			totalCount += 1


		#print "AA"
		idaapi.continue_process()

		# return values:
		#   -1 - to display a breakpoint warning dialog
		#        if the process is suspended.
		#    0 - to never display a breakpoint warning dialog.
		#    1 - to always display a breakpoint warning dialog.
		return 0


debughook = MyDbgHook()


def DoMAgic(inputAddrIn, resultAddrIn, breakAddr) :
	global debughook, possibleChars, possible26, inputAddr, resultAddr, done, ii, totalCount

	inputAddr = inputAddrIn
	resultAddr = resultAddrIn
	done = 0
	ii[0] = 2
	ii[1] = 44
	ii[2] = 39
	ii[3] = 24
	ii[4] = 17
	ii[5] = 37
	ii[6] = 44
	ii[7] = 55
	ii[8] = 60
	ii[9] = 12
	ii[10] = 41
	ii[11] = 47
	ii[12] = 15
	ii[13] = 24
	ii[14] = 16
	ii[15] = 14
	ii[16] = 39
	ii[17] = 38
	ii[18] = 24
	ii[19] = 43
	ii[20] = 43
	ii[21] = 20
	ii[22] = 7
	ii[23] = 42
	ii[24] = 24
	ii[25] = 39
	ii[26] = 12
	ii[27] = 24
	ii[28] = 34
	ii[29] = 32
	ii[30] = 0
	ii[31] = 0
	totalCount = 0

	a = Byte(inputAddr)
	print "31:", hex(a)

	for i in range(0, 32) :
		PatchByte(inputAddr + i, 0x41)

	PatchByte(inputAddr + 0, ord(possibleChars[ ii[0] ]))
	PatchByte(inputAddr + 1, ord(possibleChars[ ii[1] ]))
	PatchByte(inputAddr + 2, ord(possibleChars[ ii[2] ]))
	PatchByte(inputAddr + 3, ord(possibleChars[ ii[3] ]))
	PatchByte(inputAddr + 4, ord(possibleChars[ ii[4] ]))
	PatchByte(inputAddr + 5, ord(possibleChars[ ii[5] ]))
	PatchByte(inputAddr + 6, ord(possibleChars[ ii[6] ]))
	PatchByte(inputAddr + 7, ord(possibleChars[ ii[7] ]))
	PatchByte(inputAddr + 8, ord(possibleChars[ ii[8] ]))
	PatchByte(inputAddr + 9, ord(possibleChars[ ii[9] ]))
	PatchByte(inputAddr + 10, ord(possibleChars[ ii[10] ]))
	PatchByte(inputAddr + 11, ord(possibleChars[ ii[11] ]))
	PatchByte(inputAddr + 12, ord(possibleChars[ ii[12] ]))
	PatchByte(inputAddr + 13, ord(possibleChars[ ii[13] ]))
	PatchByte(inputAddr + 14, ord(possibleChars[ ii[14] ]))
	PatchByte(inputAddr + 15, ord(possibleChars[ ii[15] ]))
	PatchByte(inputAddr + 16, ord(possibleChars[ ii[16] ]))
	PatchByte(inputAddr + 17, ord(possibleChars[ ii[17] ]))
	PatchByte(inputAddr + 18, ord(possibleChars[ ii[18] ]))
	PatchByte(inputAddr + 19, ord(possibleChars[ ii[19] ]))
	PatchByte(inputAddr + 20, ord(possibleChars[ ii[20] ]))
	PatchByte(inputAddr + 21, ord(possibleChars[ ii[21] ]))
	PatchByte(inputAddr + 22, ord(possibleChars[ ii[22] ]))
	PatchByte(inputAddr + 23, ord(possibleChars[ ii[23] ]))
	PatchByte(inputAddr + 24, ord(possibleChars[ ii[24] ]))
	PatchByte(inputAddr + 25, ord(possibleChars[ ii[25] ]))
	PatchByte(inputAddr + 26, ord(possibleChars[ ii[26] ]))
	PatchByte(inputAddr + 27, ord(possibleChars[ ii[27] ]))
	PatchByte(inputAddr + 28, ord(possibleChars[ ii[28] ]))
	PatchByte(inputAddr + 29, ord(possibleChars[ ii[29] ]))
	PatchByte(inputAddr + 30, ord(possibleChars[ ii[30] ]))
	PatchByte(inputAddr + 31, ord(possibleChars[ ii[31] ]))

	add_bpt(breakAddr, 0, BPT_SOFT)
	enable_bpt(breakAddr, True)

	# Remove an existing debug hook
	try:
		if debughook:
			print("Removing previous hook ...")
			debughook.unhook()
	except:
		pass

	debughook = MyDbgHook()
	debughook.hook()

	continue_process()
	GetDebuggerEvent(WFNE_SUSP, -1)

	return

