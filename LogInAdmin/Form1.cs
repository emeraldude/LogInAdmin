using System;
using System.Collections.Generic;
using System.ComponentModel;
using System.Data;
using System.Data.SqlClient;
using System.Drawing;
using System.Linq;
using System.Security.Cryptography;
using System.Text;
using System.Threading.Tasks;
using System.Windows.Forms;

namespace LogInAdmin
{
    public partial class Form1 : Form
    {
        //Connects to the Log In Database
        //Enter your SQL server name and database name there
        //Use the SQL file provided
        public static SqlConnection SQLConnection = new SqlConnection(@"Data Source= [Your machine name and SQL server name] ;Database= [Your database name] ;Integrated Security=True");
        //Generates new command
        public static SqlCommand SQLCommand = new SqlCommand();
        //The pointer variable for reading SQL Data
        public static SqlDataReader SQLDataReader;
        public Form1()
        {
            InitializeComponent();
        }

        private void buttonLogIn_Click(object sender, EventArgs e)
        {
            //Get information from the text box
            string username = textBoxUsername.Text;
            string password = textBoxPassword.Text;
            //Salt and hashing is good practice
            string salt = "";
            string hashedPassword = "";
            //Username limit is 16 characters
            if (username.Length > 16)
            {
                MessageBox.Show("Username exceeds 16 characters");
                return;
            }
            //Retrieve the salt
            try
            {
                //Parameterizing prevents SQL injection attacks
                SQLCommand = new SqlCommand("select salt from Accounts where username =@username");
                SQLConnection.Close();
                SQLCommand.Connection = SQLConnection;
                SQLConnection.Open();
                SqlParameter parameter = new SqlParameter("@username", SqlDbType.VarChar, 16);
                parameter.Value = username;
                SQLCommand.Parameters.Add(parameter);
                SQLDataReader = SQLCommand.ExecuteReader();
                //Retrieve the salt
                if (SQLDataReader.HasRows)
                {
                    while (SQLDataReader.Read())
                    {
                        salt = SQLDataReader.GetString(0);
                    }
                }
                else
                {
                    //Username doesn't exist and it's free to use
                    MessageBox.Show("This username has not been registered yet");
                    return;
                }
            }
            catch (Exception ex)
            {
                System.Diagnostics.StackTrace trace = new System.Diagnostics.StackTrace(ex, true);
                MessageBox.Show(ex.Message);
                MessageBox.Show(trace.GetFrame(trace.FrameCount - 1).GetFileName());
                MessageBox.Show(trace.GetFrame(trace.FrameCount - 1).GetFileLineNumber().ToString());
                MessageBox.Show("Salt");
                return;
            }
            //Retrieve the hashed password
            try
            {
                SQLCommand = new SqlCommand("select password from Accounts where username =@username");
                SQLConnection.Close();
                SQLCommand.Connection = SQLConnection;
                SQLConnection.Open();
                SqlParameter parameter = new SqlParameter("@username", SqlDbType.VarChar, 16);
                parameter.Value = username;
                SQLCommand.Parameters.Add(parameter);
                SQLDataReader = SQLCommand.ExecuteReader();
                if (SQLDataReader.HasRows)
                {
                    while (SQLDataReader.Read())
                    {
                        hashedPassword = SQLDataReader.GetString(0);
                    }
                }
                else
                {
                    MessageBox.Show("This username has not been registered yet");
                    return;
                }
            }
            catch (Exception ex)
            {
                MessageBox.Show(ex.Message);
                return;
            }
            //Hash the passowrd
            SHA256 sha256 = SHA256.Create();
            string passwordAndSalt = password + salt;
            byte[] passwordAndSaltBytes = System.Text.Encoding.UTF8.GetBytes(passwordAndSalt);
            byte[] guessBytes = sha256.ComputeHash(passwordAndSaltBytes);
            string guess = System.Text.Encoding.UTF8.GetString(guessBytes);
            //Compare the password, if correct login else password is incorrect
            if (guess == hashedPassword)
            {
                MessageBox.Show("Logged in as " + username);
            }
            else
            {
                MessageBox.Show("Incorrect password.");
            }
        }
        /// <summary>
        /// Create an account
        /// </summary>
        /// <param name="sender"></param>
        /// <param name="e"></param>
        private void buttonCreateAccount_Click(object sender, EventArgs e)
        {
            //Get the information
            string username = textBoxUsername.Text;
            string password = textBoxPassword.Text;
            //Limit usernames to 16 characters long
            if (username.Length > 16)
            {
                MessageBox.Show("Username exceeds 16 characters");
                return;
            }
            //Validate the inputs
            if (username != "" && password != "")
            {
                //Check the strength of the password
                if (!isStrongPassword(password))
                {
                    MessageBox.Show("This passwords needs a capital letter, small letter, a number and a symbol and must be at least 8 characters long");
                    return;
                }
                //Salt and hash the password
                RandomNumberGenerator randomNumberGenerator = RandomNumberGenerator.Create();
                byte[] saltBytes = new byte[32];
                randomNumberGenerator.GetBytes(saltBytes);
                string salt = System.Text.Encoding.UTF8.GetString(saltBytes);
                string passwordAndSalt = password + salt;
                byte[] passwordAndSaltBytes = System.Text.Encoding.UTF8.GetBytes(passwordAndSalt);
                SHA256 sha256 = SHA256.Create();
                byte[] hashedPasswordBytes = sha256.ComputeHash(passwordAndSaltBytes);
                string hashedPassword = System.Text.Encoding.UTF8.GetString(hashedPasswordBytes);
                //Insert the username, salt and the hashedpassword to not store the actual password
                try
                {
                    //Insert command and SQL injection attacks are prevent with this
                    SQLCommand = new SqlCommand("Insert Into Accounts values(@username,@salt,@password)");
                    SQLConnection.Close();
                    SQLCommand.Connection = SQLConnection;
                    SQLConnection.Open();
                    SqlParameter parameter = new SqlParameter("@username",SqlDbType.VarChar,16);
                    parameter.Value = username;
                    SQLCommand.Parameters.Add(parameter);
                    parameter = new SqlParameter("@salt", SqlDbType.NVarChar);
                    parameter.Value = salt;
                    SQLCommand.Parameters.Add(parameter);
                    parameter = new SqlParameter("@password", SqlDbType.NVarChar);
                    parameter.Value = hashedPassword;
                    SQLCommand.Parameters.Add(parameter);
                    SQLCommand.ExecuteNonQuery();
                    MessageBox.Show("Created an account named: " + username);
                }
                catch (Exception ex)
                {
                    MessageBox.Show("Username already exists");
                }
            }
            else
            {
                MessageBox.Show("Please enter a username and a password before proceeding.");
            }
        }
        /// <summary>
        /// Checks if the password is using a mix of lower case letters, upper case letters, numbers and symbols
        /// </summary>
        /// <param name="password"></param>
        /// <returns></returns>
        private bool isStrongPassword(string password)
        {
            bool containsLowerCase = false;
            bool containsUpperCase = false;
            bool containsNumber = false;
            bool containsSymbol = false;
            foreach (char c in password)
            {
                if (c >= 'a' && c <= 'z')
                    containsLowerCase = true;
                else if (c >= 'A' && c <= 'Z')
                    containsUpperCase = true;
                else if (c >= '0' && c <= '9')
                    containsNumber = true;
                else
                    containsSymbol = true;
            }
            if (containsLowerCase && containsUpperCase && containsNumber && containsSymbol && password.Length >= 8)
                return true;
            else
                return false;
        }
    }
}
