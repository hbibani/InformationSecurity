#include <iostream>
using namespace std;

class SDESencryption
{
public:
	SDESencryption(string k1, string k2, string ptext)
	{
		//Initialize data
		p81 = "00000000";
		lefthalf1 = "0000";
		righthalf1 = "0000";
		delefthalf1 = "0000";
		derighthalf1 = "0000";
		expOne = "00000000";
		decrexpOne = "00000000";
		XOROne = "00000000";
		decXOROne = "00000000";
		s4s0s1 = "0000";
		decs4s0s1 = "0000";
		s5p4 = "0000";
		decs5p4 = "0000";
		s7output = "00000000";
		decs7output = "00000000";
		plaintext = ptext;
		deciphertext = ptext;
		decplaintext = "00000000";
		lefthalfpart2 = "0000";
		righthalfpart2 = "0000";

		declefthalfpart2 = "0000";
		decrighthalfpart2 = "0000";
		decpart2Exp = "00000000";
		part2Exp = "00000000";
		part2XORK2 = "00000000";
		decpart2XORK2 = "00000000";
		decpart2s0s1 = "0000";
		part2P4 = "0000";
		decpart2P4 = "0000";
		part2XOR4 = "0000";
		decpart2XOR4 = "0000";
		ciphertext = "00000000";
		key1 = k1;
		key2 = k2;
		ip[0] = 2;
		ip[1] = 6;
		ip[2] = 3;
		ip[3] = 1;
		ip[4] = 4;
		ip[5] = 8;
		ip[6] = 5;
		ip[7] = 7;
		ipminus[0] = 4;
		ipminus[1] = 1;
		ipminus[2] = 3;
		ipminus[3] = 5;
		ipminus[4] = 7;
		ipminus[5] = 2;
		ipminus[6] = 8;
		ipminus[7] = 6;
		exP[0] = 4;
		exP[1] = 1;
		exP[2] = 2;
		exP[3] = 3;
		exP[4] = 2;
		exP[5] = 3;
		exP[6] = 4;
		exP[7] = 1;
		perm4[0] = 2;
		perm4[1] = 4;
		perm4[2] = 3;
		perm4[3] = 1;
		int st0[4][4] = { {1,0,3,2}, {3,2,1,0}, {0,2,1,3}, {3,1,3,2} };
		int st1[4][4] = { {0,1,2,3}, {2,0,1,3}, {3,0,1,0}, {2,1,0,3} };

		for (int i = 0; i < 4; i++)
		{
			for (int j = 0; j < 4; j++)
			{
				s0[i][j] = st0[i][j];
				s1[i][j] = st1[i][j];
			}
		}
	}

	//step by step function which execites each function in order
	void encryptionAlg()
	{
		step1IpOne(1);
		step2ExpOne(1);
		step3XORK1(1);
		step4S0S1(1);
		step5P4(1);
		step6XOR4(1);
		step7SwapRHS6(1);

		//part2
		part2Step1EP1(1);
		part2Step2XORK2(1);
		part2Step3S0S1(1);
		part2Step4P4(1);
		part2Step5XORLH(1);
		part2Step6IP(1);
	}

	//decryption algorithm step by step function which executes it in order for decryption
	void decryptionAlg()
	{
		step1IpOne(2);
		step2ExpOne(2);
		step3XORK1(2);
		step4S0S1(2);
		step5P4(2);
		step6XOR4(2);
		step7SwapRHS6(2);

		//part2
		part2Step1EP1(2);
		part2Step2XORK2(2);
		part2Step3S0S1(2);
		part2Step4P4(2);
		part2Step5XORLH(2);
		part2Step6IP(2);
	}

private:

	//encryption strings
	string key1;
	string key2;
	string plaintext;
	string deciphertext;
	string ciphertext;
	string s4s0s1;
	string s5p4;
	string s6XOR4;
	string s7output;
	string lefthalfpart2;
	string righthalfpart2;
	string part2Exp;
	string part2XORK2;
	string part2s0s1;
	string part2P4;
	string part2XOR4;
	int exP[8];
	int s0[4][4];
	int s1[4][4];
	int ip[8];
	int ipminus[8];
	string p81;
	int perm4[4];
	string lefthalf1;
	string righthalf1;
	string expOne;
	string XOROne;

	//Decryption strings
	string delefthalf1;
	string derighthalf1;
	string decrexpOne;
	string decXOROne;
	string decs4s0s1;
	string decs5p4;
	string decs6XOR4;
	string decs7output;
	string decpart2Exp;
	string declefthalfpart2;
	string decrighthalfpart2;
	string decpart2XORK2;
	string decpart2s0s1;
	string decpart2P4;
	string decpart2XOR4;
	string decplaintext;


	//manual XOR function for 8 bit value using strings
	string XOR(string key, string output)
	{
		string out = "11111111"; //output string
		for (int i = 0; i < 8; i++)
		{
			//simplified mechanism to ensure value is correct
			if ((key[i] == '0' && output[i] == '0') || (key[i] == '1' && output[i] == '1'))
			{
				out[i] = '0';
			}
			else
			{
				out[i] = '1';
			}
		}

		return out; //return out
	}

	//manual XOR function for 4 bit value using strings
	string XOR4(string LH, string output)
	{
		string out = "1111";

		for (int i = 0; i < 8; i++)
		{
			if ((LH[i] == '0' && output[i] == '0') || (LH[i] == '1' && output[i] == '1'))
			{
				out[i] = '0';
			}
			else
			{
				out[i] = '1';
			}
		}

		return out;
	}

	//Step 1: Permutation of intial cipher/enciphered text
	void step1IpOne(int which)
	{
		string lh = "0000";
		string rh = "0000";
		string text = "00000000";

		//the algorithm changes based up on which method is being used encipherment or cipherment
		if (which == 1)
		{
			text = plaintext;
		}

		if (which == 2)
		{
			text = deciphertext;
		}

		for (int i = 0; i < 8; i++)
		{
			p81[i] = text[ip[i] - 1];
		}

		//split bits into halves
		for (int i = 0; i < 4; i++)
		{
			lh[i] = p81[i];
			rh[i] = p81[i + 4];
		}

		//set the value of the variables
		if (which == 1)
		{
			lefthalf1 = lh;
			righthalf1 = rh;
		}

		if (which == 2)
		{
			delefthalf1 = lh;
			derighthalf1 = rh;
		}
	}

	//Step 2: gets righthalf and gives expansion
	void step2ExpOne(int which)
	{
		string buffer = "00000000";
		string rh = "0000";

		//which determines which type of encipherment it is
		if (which == 1)
		{
			rh = righthalf1;
		}

		if (which == 2)
		{
			rh = derighthalf1;
		}

		for (int i = 0; i < 8; i++)
		{
			buffer[i] = rh[exP[i] - 1];
		}

		//allocate the correct string depending on encipherment
		if (which == 1)
		{
			expOne = buffer;
		}

		if (which == 2)
		{
			decrexpOne = buffer;
		}
	}

	//Step 3: XOR with Key1 or Key2 [depending up on type]
	void step3XORK1(int which)
	{

		//which determines which type of encipherment it is
		if (which == 1)
		{
			XOROne = XOR(key1, expOne);
		}

		if (which == 2)
		{
			decXOROne = XOR(key2, decrexpOne);
		}
	}

	//Step 4: S0 and S1 functions and output strings
	void step4S0S1(int which)
	{
		//set strings
		string LHout;
		string LHinner;
		string LH;
		string RH;
		string RHout;
		string RHinner;
		string buffer8 = "00000000";
		string buffer4;


		//which determines which type of encipherment it is
		if (which == 1)
		{
			buffer8 = XOROne;
		}

		if (which == 2)
		{
			buffer8 = decXOROne;
		}

		//get the right values [inner or outer of the string]
		LHout.push_back(buffer8[0]);
		LHout.push_back(buffer8[3]);
		LHinner.push_back(buffer8[1]);
		LHinner.push_back(buffer8[2]);
		RHout.push_back(buffer8[4]);
		RHout.push_back(buffer8[7]);
		RHinner.push_back(buffer8[5]);
		RHinner.push_back(buffer8[6]);
		//call the solver function with inner or outer 
		LH = S0solver(LHout, LHinner); //retrieve the left-half
		RH = S1solver(RHout, RHinner); //retrieve right half

		//amalgamate values from RH and LH and put them into string
		buffer4.push_back(LH[0]);
		buffer4.push_back(LH[1]);
		buffer4.push_back(RH[0]);
		buffer4.push_back(RH[1]);


		//give the value of the buffer retrieved depending on encipherment method
		if (which == 1)
		{
			s4s0s1 = buffer4;
		}

		if (which == 2)
		{
			decs4s0s1 = buffer4;
		}
	}


	//S1 solver function
	string S1solver(string out, string inner)
	{
		int xaxis;
		int yaxis;
		string output;

		//get values of x-axis of s1 depending on the values of the inner
		if (out[1] == '1' && out[0] == '1')
		{
			xaxis = 3;
		}
		else if (out[1] == '0' && out[0] == '1')
		{
			xaxis = 2;
		}
		else if (out[1] == '1' && out[0] == '0')
		{
			xaxis = 1;
		}
		else
		{
			xaxis = 0;
		}


		//get values of y-axis of s1 depending on the values of the inner
		if (inner[1] == '1' && inner[0] == '1')
		{
			yaxis = 3;
		}
		else if (inner[1] == '0' && inner[0] == '1')
		{
			yaxis = 2;
		}
		else if (inner[1] == '1' && inner[0] == '0')
		{
			yaxis = 1;
		}
		else
		{
			yaxis = 0;
		}

		//check values from the 2-d array of S1
		if (s1[xaxis][yaxis] == 3)
		{
			output.push_back('1');
			output.push_back('1');
		}

		if (s1[xaxis][yaxis] == 0)
		{
			output.push_back('0');
			output.push_back('0');
		}

		if (s1[xaxis][yaxis] == 1)
		{
			output.push_back('0');
			output.push_back('1');
		}

		if (s1[xaxis][yaxis] == 2)
		{
			output.push_back('1');
			output.push_back('0');
		}

		return output;
	}

	//S0 solver function
	string S0solver(string out, string inner)
	{
		int xaxis;
		int yaxis;
		string output;

		//give the value of x-axis of s0 dpending on input values
		if (out[1] == '1' && out[0] == '1')
		{
			xaxis = 3;
		}
		else if (out[1] == '0' && out[0] == '1')
		{
			xaxis = 2;
		}
		else if (out[1] == '1' && out[0] == '0')
		{
			xaxis = 1;
		}
		else
		{
			xaxis = 0;
		}

		//get values of y-axis of s0 depending on the values of the inner
		if (inner[1] == '1' && inner[0] == '1')
		{
			yaxis = 3;
		}
		else if (inner[1] == '0' && inner[0] == '1')
		{
			yaxis = 2;
		}
		else if (inner[1] == '1' && inner[0] == '0')
		{
			yaxis = 1;
		}
		else
		{
			yaxis = 0;
		}

		//check values from the 2-d array of S0
		if (s0[xaxis][yaxis] == 3)
		{
			output.push_back('1');
			output.push_back('1');
		}

		if (s0[xaxis][yaxis] == 0)
		{
			output.push_back('0');
			output.push_back('0');
		}

		if (s0[xaxis][yaxis] == 1)
		{
			output.push_back('0');
			output.push_back('1');
		}

		if (s0[xaxis][yaxis] == 2)
		{
			output.push_back('1');
			output.push_back('0');
		}

		return output;
	}


	//Step 5 - Permutation of output from S0/S1 function
	void step5P4(int which)
	{
		//simple permutation, which is determined by encipherment type
		for (int i = 0; i < 4; i++)
		{
			if (which == 1)
			{
				s5p4[i] = s4s0s1[perm4[i] - 1];
			}

			if (which == 2)
			{
				decs5p4[i] = decs4s0s1[perm4[i] - 1];
			}
		}
	}


	//Step 6: XOR with LH of first
	void step6XOR4(int which)
	{
		if (which == 1)
		{
			s6XOR4 = XOR4(lefthalf1, s5p4);
		}

		if (which == 2)
		{
			decs6XOR4 = XOR4(delefthalf1, decs5p4);
		}
	}


	//Step 7: Swap step
	void step7SwapRHS6(int which)
	{

		//put left half in right half
		//put right half in left-half
		if (which == 1)
		{
			for (int i = 0; i < 4; i++)
			{
				s7output[i] = righthalf1[i];
			}

			for (int i = 4; i < 8; i++)
			{
				s7output[i] = s6XOR4[i - 4];
			}
		}

		if (which == 2)
		{
			for (int i = 0; i < 4; i++)
			{
				decs7output[i] = derighthalf1[i];
			}

			for (int i = 4; i < 8; i++)
			{
				decs7output[i] = decs6XOR4[i - 4];
			}
		}
	}

	//Part 2: Step 1: Expansion and Right half - inputs are taken from first half output
	void part2Step1EP1(int which)
	{
		string lefthalfbuffer = "0000";
		string righthalfbuffer = "0000";
		string expansion = "00000000";
		string s7outputbuffer = "00000000";

		//determine which buffer to pick
		if (which == 1)
		{
			s7outputbuffer = s7output;
		}

		if (which == 2)
		{
			s7outputbuffer = decs7output;
		}

		//make the appropriate buffers
		for (int i = 0; i < 4; i++)
		{
			lefthalfbuffer[i] = s7outputbuffer[i];
		}

		for (int i = 0; i < 4; i++)
		{
			righthalfbuffer[i] = s7outputbuffer[i + 4];
		}

		//expansion of the righthalf 
		for (int i = 0; i < 8; i++)
		{
			expansion[i] = righthalfbuffer[exP[i] - 1];
		}

		//allocate the right values to the ones stored for reference
		if (which == 1)
		{
			part2Exp = expansion;
			lefthalfpart2 = lefthalfbuffer;
			righthalfpart2 = righthalfbuffer;
		}

		if (which == 2)
		{
			decpart2Exp = expansion;
			declefthalfpart2 = lefthalfbuffer;
			decrighthalfpart2 = righthalfbuffer;
		}
	}

	//Part 2: Step 2: XOR with K2 or K1 Depending upon encipherment type
	void part2Step2XORK2(int which)
	{
		if (which == 1)
		{
			part2XORK2 = XOR(key2, part2Exp);
		}

		if (which == 2)
		{
			decpart2XORK2 = XOR(key1, decpart2Exp);
		}
	}


	//Part 2: Step 3: S0 and S1 Solvers
	void part2Step3S0S1(int which)
	{
		string LHout;
		string LHinner;
		string LH;
		string RH;
		string buffer8 = "00000000";
		string buffer4;
		string RHout;
		string RHinner;

		//get buffer depending upon encipherment
		if (which == 1)
		{
			buffer8 = part2XORK2;
		}

		if (which == 2)
		{
			buffer8 = decpart2XORK2;
		}

		//get the values for x-axis and y-axis
		LHout.push_back(buffer8[0]);
		LHout.push_back(buffer8[3]);
		LHinner.push_back(buffer8[1]);
		LHinner.push_back(buffer8[2]);
		RHout.push_back(buffer8[4]);
		RHout.push_back(buffer8[7]);
		RHinner.push_back(buffer8[5]);
		RHinner.push_back(buffer8[6]);

		//once the axis is taken call solver
		LH = S0solver(LHout, LHinner);
		RH = S1solver(RHout, RHinner);

		//amalgamate the values to produce string
		buffer4.push_back(LH[0]);
		buffer4.push_back(LH[1]);
		buffer4.push_back(RH[0]);
		buffer4.push_back(RH[1]);

		//give the value from the buffer into desired value
		if (which == 1)
		{
			part2s0s1 = buffer4;
		}

		if (which == 2)
		{
			decpart2s0s1 = buffer4;
		}
	}


	//Part 2: Step 4: 4-Permutation 
	void part2Step4P4(int which)
	{

		//simple 4 bit perumtation function
		//which determines the type and the output source
		if (which == 1)
		{
			for (int i = 0; i < 4; i++)
			{
				part2P4[i] = part2s0s1[perm4[i] - 1];
			}
		}

		if (which == 2)
		{
			for (int i = 0; i < 4; i++)
			{
				decpart2P4[i] = decpart2s0s1[perm4[i] - 1];
			}
		}
	}

	//Part 2: Step 5: XOR with initial LH 
	void part2Step5XORLH(int which)
	{
		//calls manual 4bit XOR function for strings
		if (which == 1)
		{
			part2XOR4 = XOR4(lefthalfpart2, part2P4);
		}

		if (which == 2)
		{
			decpart2XOR4 = XOR4(declefthalfpart2, decpart2P4);
		}
	}


	//Part 2: Step 6: Permutation function
	void part2Step6IP(int which)
	{
		string input;
		string p2XOR4 = "0000";
		string rhp2 = "0000";

		if (which == 1)
		{
			p2XOR4 = part2XOR4;
			rhp2 = righthalfpart2;

			//amalgamate inputs
			for (int i = 0; i < 4; i++)
			{
				input.push_back(p2XOR4[i]); //from step 5
			}

			for (int i = 0; i < 4; i++)
			{
				input.push_back(rhp2[i]); //right half from initial
			}

			//permutation of amalgmated strings
			for (int i = 0; i < 8; i++)
			{
				ciphertext[i] = input[ipminus[i] - 1];
			}
		}

		if (which == 2)
		{
			p2XOR4 = decpart2XOR4;
			rhp2 = decrighthalfpart2;
			for (int i = 0; i < 4; i++)
			{
				input.push_back(p2XOR4[i]); //from step 5
			}

			for (int i = 0; i < 4; i++)
			{
				input.push_back(rhp2[i]); //from right-half initial
			}

			//permutation function
			for (int i = 0; i < 8; i++)
			{
				decplaintext[i] = input[ipminus[i] - 1];
			}
		}

		//print-out final encryption or decryption
		if (which == 1)
		{
			cout << "Encryption = " << ciphertext << endl;
		}

		if (which == 2)
		{
			cout << "Decryption = " << decplaintext;
		}

	}
};


//Key Generator Class
class SDESkey
{
public:
	string key;
	string plaintext;
	string ciphertext;

	//initialize numbers;
	SDESkey()
	{
		leftshift1 = "0000000000";
		leftshift2 = "0000000000";
		k1 = "00000000";
		k2 = "00000000";
		keyp10step1 = "0000000000";
		p10[0] = 3;
		p10[1] = 5;
		p10[2] = 2;
		p10[3] = 7;
		p10[4] = 4;
		p10[5] = 10;
		p10[6] = 1;
		p10[7] = 9;
		p10[8] = 8;
		p10[9] = 6;
		p8[0] = 6;
		p8[1] = 3;
		p8[2] = 7;
		p8[3] = 4;
		p8[4] = 8;
		p8[5] = 5;
		p8[6] = 10;
		p8[7] = 9;
		cout << "Enter the key of size 10: " << endl;
		getline(cin, key);

		while (key.length() != 10)
		{
			cout << "Enter the key of size 10 please: " << endl;
			getline(cin, key);
		}
	}

	//return keys
	void SDESank(string& key1, string& key2)
	{
		keyGenerator();
		cout << "K1:" << k1 << endl;
		cout << "K2:" << k2 << endl;
		key1 = k1;
		key2 = k2;
	}

private:
	int p10[10];
	int p8[10];
	string keyp10step1;
	string leftshift1;
	string leftshift2;
	string k1;
	string k2;

	//generate key function
	void keyGenerator()
	{
		permutation10();
		lshift1();
		permutation8(1);
		lshift2();
		permutation8(2);

	}

	//initial p-10 permutation
	void permutation10()
	{
		cout << key << endl;
		for (int i = 0; i < 10; i++)
		{
			keyp10step1[i] = key[p10[i] - 1];
		}
	}

	//left shift 1
	void lshift1()
	{
		for (int i = 0; i < 5; i++)
		{
			if (i != 4)
			{
				leftshift1[i] = keyp10step1[i + 1];
				leftshift1[i + 5] = keyp10step1[i + 5 + 1];
			}
			else
			{
				leftshift1[i] = keyp10step1[0];
				leftshift1[i + 5] = keyp10step1[5];
			}
		}
	}

	/*permutation-8 key generator*/
	void permutation8(int k)
	{
		//if k == 1 then for key 1
		if (k == 1)
		{
			for (int i = 0; i < 8; i++)
			{
				k1[i] = leftshift1[p8[i] - 1];
			}
		}

		//if k == 2 then do for second left shift
		if (k == 2)
		{
			for (int i = 0; i < 8; i++)
			{
				k2[i] = leftshift2[p8[i] - 1];
			}
		}
	}

	/*Left shift operations*/
	void lshift2()
	{
		for (int i = 0; i < 5; i++)
		{
			if (i != 3)
			{
				leftshift2[i] = leftshift1[i + 2];
				leftshift2[i + 5] = leftshift1[i + 5 + 2];
			}

			if (i == 3)
			{
				leftshift2[i] = leftshift1[0];
				leftshift2[i + 5] = leftshift1[5];
			}

			if (i == 4)
			{
				leftshift2[i] = leftshift1[1];
				leftshift2[i + 5] = leftshift1[6];
			}
		}
	}
};



int main()
{
	int exit = 1;

	while (exit == 1)
	{
		SDESkey test; //enter key
		string choice;
		string plaintext; //plain text
		string ciphertext;//cipher text
		cout << "Enter an option" << endl;
		cout << "1: Encryption" << endl;
		cout << "2: Decryption" << endl;
		getline(cin, choice);
		string key1;
		string key2;

		//encryption or decryption choice
		if (choice == "1")
		{
			cout << "Enter plaintext of size 8: " << endl;
			getline(cin, plaintext);

			while (plaintext.length() != 8)
			{
				cout << "Enter plaintext of size 8: " << endl;
				getline(cin, plaintext);
			}

			cout << "Plain-Text: " << plaintext << endl;
			test.SDESank(key1, key2);
			SDESencryption sdes(key1, key2, plaintext);
			sdes.encryptionAlg();
		}
		else
		{
			cout << "Enter ciphertext of size 8: " << endl;
			getline(cin, ciphertext);

			while (ciphertext.length() != 8)
			{
				cout << "Enter plaintext of size 8: " << endl;
				getline(cin, plaintext);
			}

			cout << "Cipher-text: " << ciphertext << endl;
			test.SDESank(key1, key2);
			SDESencryption sdes(key1, key2, ciphertext);
			sdes.decryptionAlg();
		}

		//prompt to continue or discontinue
		cout << endl;
		cout << "Would you like to continue? 1 for yes, and 0 for no" << endl;
		cin >> exit;
		cin.ignore();
		cout << "---------------------------------------------" << endl;
	}
}

