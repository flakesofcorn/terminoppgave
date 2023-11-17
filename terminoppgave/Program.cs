using System;
using System.Data;
using System.Data.SqlClient;
using System.Data.SqlTypes;
using System.Security;
using System.Security.Cryptography;
using Microsoft.AspNetCore.Cryptography.KeyDerivation;

class Program
{

    static string connectionString = "Data Source=DESKTOP-EVCQ0V1\\SQLEXPRESS;Initial Catalog=userdb;Integrated Security=True";


    static void Main()
    {
        Console.WriteLine("welcome for command help type help, to continue loggin in with 'login'");
        Console.Write("$$- ");
        string input = Console.ReadLine();

        switch (input)
        {
            case "help":
                help();
                break;
            case "login":
                Console.Write("username: ");
                string username = Console.ReadLine();

                Console.Write("password: ");
                string password = GetMaskedInput();

                bool valid = CheckUser(username, password);

                if (valid)
                {
                    Console.Write("\n");
                    Console.WriteLine("logged in");
                    index();
                }
                break;
            case "mkusr":
                Console.Write("username: ");
                string new_username = Console.ReadLine();

                Console.Write("password: ");
                string new_password = GetMaskedInput();

                Console.Write("email: ");
                string email = Console.ReadLine();

                create_user(new_username, new_password, email);


                break;
            case "quit":
                System.Environment.Exit(0);
                break;
            case "":
                Main();
                break;
        }

    }



    static string GetMaskedInput()
    {
        string input = "";
        ConsoleKeyInfo keyInfo;

        do
        {
            keyInfo = Console.ReadKey(true);

            if (keyInfo.Key != ConsoleKey.Enter)
            {
                input += keyInfo.KeyChar;
                Console.Write("*");
            }
        }

        while (keyInfo.Key != ConsoleKey.Enter);

        return input;
    }

    static int number = 1;

    static void help()
    {
        Console.WriteLine("-login       |       to login to appllication requires valid username and password.");
        Console.WriteLine("-mkusr       |       use to create a new user.");
        Console.WriteLine("-quit        |       exits the program.");
        Console.WriteLine("-users       |       displays all users currently registered(only accesible by admin users)");

        Main();
    }
    static void hash(string password)
    {



    }


    static void create_user(string username, string password, string email)
    {
        using (SqlConnection connection = new SqlConnection(connectionString))
        {
            connection.Open();

            byte[] salt = RandomNumberGenerator.GetBytes(128 / 8);
            Console.WriteLine($"salt: {Convert.ToBase64String(salt)}");

            string hash = Convert.ToBase64String(KeyDerivation.Pbkdf2(
                password: password!,
                salt: salt,
                prf: KeyDerivationPrf.HMACSHA256,
                iterationCount: 100000,
                numBytesRequested: 256 / 8));



            string query = "INSERT INTO Users_table (Username, Password, admin, Email, salt) VALUES (@Username, @Password, @admin, @Email, @salt)";
            using (SqlCommand command = new SqlCommand(query, connection))
            {
                command.Parameters.AddWithValue("@Username", username);
                command.Parameters.AddWithValue("@Password", hash);
                command.Parameters.AddWithValue("@email", email);
                command.Parameters.AddWithValue("@salt", Convert.ToBase64String(salt));
                command.Parameters.AddWithValue("@admin", 0);

                command.ExecuteNonQuery();
                connection.Close();



            }
            Main();
        }
    }



    static bool CheckUser(string username, string password)
    {
        using (SqlConnection connection = new SqlConnection(connectionString))
        {
            connection.Open();



            string hash;
            string salt;


            string query = "SELECT password, salt FROM Users_table WHERE Username = @Username";
            using (SqlCommand command = new SqlCommand(query, connection))
            {
                command.Parameters.AddWithValue("@Username", username);


                using (SqlDataReader reader = command.ExecuteReader())
                {
                    if (reader.Read())
                    {
                        hash = reader.GetString(0);
                        salt = reader.GetString(0);
                        
                    }

                }

                salt = Convert.ToByte(salt);

                string hash2 = Convert.ToBase64String(KeyDerivation.Pbkdf2(
                    password: password!,
                    salt: salt,
                    prf: KeyDerivationPrf.HMACSHA256,
                    iterationCount: 100000,
                    numBytesRequested: 256 / 8));


                int count = (int)command.ExecuteScalar();


                connection.Close();
                return count > 0;

            }
        }
    }

    static void index()
    {
        Console.Write("\n");

        Console.Write("$$- ");

        string input = Console.ReadLine();

        switch (input)
        {
            case "help":
                help();
                break;

            case "logout":
                Main();

                break;

            case "users":
                display_users();

                break;
            case "quit":

                System.Environment.Exit(0);
                break;
            case "":
                index();
                break;

        }


    }
    static void display_users()
    {
        using (SqlConnection connection = new SqlConnection(connectionString))
        {
            connection.Open();


            string query = "SELECT * FROM Users_table";
            using (SqlCommand command = new SqlCommand(query, connection))
            {
                using (SqlDataReader reader = command.ExecuteReader())
                {
                    while (reader.Read())
                    {
                        Console.WriteLine($"{reader["id"]}, {reader["username"]}, {reader["email"]}, {reader["admin"]}");
                    }

                }

                command.ExecuteNonQuery();
                connection.Close();
            }
            index();
        }
    }
}