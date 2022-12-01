
#include <iostream>
#include <cmath>
#include<bits/stdc++.h> 
#include<vector>

using namespace std;

//Iterative Function to calculate (x^y)%p in O(log y)
int power(int x, int y, int p)
{
	int res = 1;  //Initialize result  
	int c = 0;
	int ctest = y;
	int z = pow(2, 30);
	int countdown;

	if (x == 0) return 0; // In case x is divisible by p; 

	//we find the position where the first value of a "1" is
	//then we can determine the value of the count-down
	for (int i = 0; i < 31; i++)
	{
		if (y & z)
		{
			countdown = 30 - i;
			break;
		}

		z = z >> 1;
	}

	//following the lecture the c is calculated
	//and the result sent back
	for (int i = countdown; i >= 0; i--)
	{
		c = 2 * c;
		res = fmod((res * res), p);

		if (z & y)
		{
			c = c + 1;
			res = fmod((res * x), p);
		}

		z = z >> 1;
	}

	//cout << endl << "c and y: "  << c << " " << ctest << endl;
	return res;
}

// Returns gcd of a and b 
int gcdCalc(int a, int y)
{

	int tempValue;
	while (1)
	{
		//calculates remainder
		tempValue = power(a, 1, y);

		if (tempValue == 0)
		{
			/*
				returns the last remainder[GCD] which was stored
				from previous tempValue this algorithm doesn't store
				multiplication value
			*/
			return y;
		}

		//get preivous remainder  
		a = y;
		//y now = current remainder 
		y = tempValue;
	}
}

//Check if prime 
bool isPrimeNumber(int n)
{
	// Bottom case 
	if (n <= 1)
	{
		return false;
	}

	/*
		if a value between 2 and n-1 has a divisor
		then it is not prime
	*/
	for (int i = 2; i < n; i++)
	{
		if (power(n, 1, i) == 0)
		{
			return false;
		}
	}

	return true;
}

//modular inverse
int modInv(int e, int phi)
{
	
	e = power(e, 1, phi);
	/*
		we go through each value between x and m-1
		and check each value to see if mod inverse = 1
		this has complexity O(n), which was simpler than
		the other methods
	*/
	for (int x = 1; x < phi; x++)
	{
		if (power((e * x), 1, phi) == 1)
		{
			return x;
		}
	}

}


// Code to demonstrate RSA algorithm 
int main()
{
	int test = 1;
	cout << "Demonstration: RSA Algorithm " << endl << endl;
	while (test == 1)
	{
		int p;
		int q;
		int n;
		int phi;
		int e;
		int msg;
		int d;
		int c;
		int m;
		cout << "Enter p: " << endl;
		cin >> p;

		//check if prime
		while (!isPrimeNumber(p))
		{
			cout << "Please enter a prime number: " << endl;
			cin >> p;
		}

		cout << "Enter q: " << endl;
		cin >> q;

		//check if prime and different from p
		while (!isPrimeNumber(q) || (p == q))
		{
			cout << "Please enter a prime number different from p: " << p << endl;
			cin >> q;
		}

		n = p * q;
		phi = (q - 1) * (p - 1);
		cout << "Enter e: " << endl;
		cin >> e;

		while ((e <= 1 || e >= phi) || (gcdCalc(e, phi) != 1))
		{
			cout << "Please enter a value e less than " << phi << " and greater than 1 " << endl;
			cout << "The value must also be relatively prime to phi: " << phi << endl;
			cin >> e;
		}

		cout << "Please enter encryption message: " << endl;
		cin >> msg;
		cout << "Message data = " << msg << endl;

		while (msg >= n || msg <= (-1 * n))
		{
			cout << "Please enter a value msg less than " << n << endl;
			cin >> msg;
			cout << "Message data = " << msg << endl;
		}

		//get modular inverse
		d = modInv(e, phi);
		//Encryption c = (msg ^ e) % n 
		c = power(msg, e, n);

		//print inputs
		cout << "----------------Total Input-----------------------" << endl;
		cout << "p = " << p << endl;
		cout << "q = " << q << endl;
		cout << "e = " << e << endl;
		cout << "d = " << d << endl;
		cout << "m = " << msg << endl;
		cout << "n = " << p * q << endl;
		cout << "Phi(n) = " << (p - 1) * (q - 1) << endl;
		cout << "--------------------------------------------------" << endl;

		cout << "----------------Encrypted Message-----------------" << endl;
		cout << "\nEncrypted data = " << c << endl;

		// Decryption m = (c ^ d) % n 
		m = power(c, d, n);
		cout << "----------------Decrypted Message-----------------" << endl;
		cout << "\nOriginal Message Sent = " << m << endl;
		cout << "--------------------------------------------------" << endl;

		cout << "Would you like to go again? 1 for yes, 0 for no. " << endl;
		cin >> test;
		cin.ignore();
	}

	return 0;
}

