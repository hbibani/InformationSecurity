// A C++ program to illustrate Caesar Cipher Technique 
#include <iostream> 
#include <math.h>       /* fmod */
using namespace std;



int myCustomModulo(const int& a, const int& b)
{
    return (a % b + b) % b;
}

// This function receives text and shift and 
// returns the encrypted text 
string encrypt(string text, int s)
{
    string result = "";

    // traverse text 
    for (int i = 0; i < text.length(); i++)
    {
        // apply transformation to each character 
        // Encrypt Uppercase letters
		if(!isspace(text[i]) && isalpha(text[i]))
		{
			if (isupper(text[i]))
	            result += char(myCustomModulo(int(text[i] + s - 65), 26) + 65);
	        else
	            result += char(myCustomModulo(int(text[i] + s - 97), 26) + 97);
		}

    }

    // Return the resulting string 
    return result;
}

// This function receives text and shift and 
// returns the encrypted text 
string decrypt(string text, int s)
{
    string result = "";

    // traverse text 
    for (int i = 0; i < text.length(); i++)
    {
        // apply transformation to each character 
        // Encrypt Uppercase letters
		if(!isspace(text[i]) && isalpha(text[i]))
		{
			if (isupper(text[i]))
	            result += char(myCustomModulo(int(text[i] - s - 65), 26) + 65);
	        else
	            result += char(myCustomModulo(int(text[i] - s - 97), 26) + 97);	
		}
    }
    // Return the resulting string 
    return result;
}


// Driver program to test the above function 
int main()
{
    int key = 0;
    string text;
    int x = 1;
    int decide;
    int test = 1;
    
    while(x == 1)
    {
    	cout << "Enter a decision: " << endl;
    	cout << "(1) Enter Key"  << endl;
    	cout << "(2) Encrypt" << endl;
    	cout << "(3) Decrypt" << endl;
    	cout << "(4) Exit" << endl;
    	cout << "Choice: ";
		cin >> decide;
		
		switch( decide )
		{
			case 1: 
				cout << "Key Choice: ";
				cin >> key;
				while( key < 0 )
				{
					cout << "Invalid Choice please pick a number greater than 0: ";
					cin >> key;
				}
				break;
			case 2: 
				cout << "Encrypt String: ";
				cin.ignore( );
				getline( cin , text );
				while( test == 1 )
				{
					for( int i = 0; i < text.length( ); i++ )
					{
						if( !isalpha( text[ i ] ) && !isspace( text[ i ] ) )
						{
							break;
						}
						
						if( i == ( text.length( ) - 1 ) )
						{
							test = 0;
						}
					}
					
					if( test == 0 )
					{
						break;
					}
					
					cout << endl;
					text = "";
					cout << "Encryption must be alphabetic characters: ";
					getline( cin , text );
				}
				test = 1;
				cout << "Cipher: " << encrypt( text , key ) << endl << endl;
				break;
			case 3:
				cout << "Decrypt String: ";
				cin.ignore( );
				getline( cin, text );
				while( test == 1 )
				{
					for( int i = 0; i < text.length( ); i++ )
					{
						if( !isalpha( text[ i ] ) && !isspace( text[ i ] ) )
						{
							break;
						}
						
						if( i == ( text.length( ) - 1 ) )
						{
							test = 0;
						}
					}
					
					if( test == 0 )
					{
						break;
					}
					cout << endl;
					text = "";
					cout << "Decryption must be alphabetic characters: ";
					getline( cin , text );
				}
				test = 1;
				cout << "Plain-Text: " << decrypt( text , key ) << endl << endl;
				break;
			case 4:
				x = 0;
				break;
		}
	}
    
    return 0;
}
