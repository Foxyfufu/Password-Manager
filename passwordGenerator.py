import random
import string

class passwordGenerator():

	def generatePassword(self):
		characters = list(string.ascii_letters + string.digits + "!@#$%^&*()")
		random.shuffle(characters)
		temp = random.sample(characters, 16) #elements picked not replaced
		randomPassword = "".join(temp)	
		return randomPassword

	def generateOTP(self):
		characters = list(string.digits)
		random.shuffle(characters)
		temp = random.sample(characters, 6)
		OTP = "".join(temp)	
		return OTP
