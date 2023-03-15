$serverName = "20.242.43.183" # Replace with the name of your SQL Server instance
$databaseName = "master" # Replace with the name of your database
$username = "cyber-lab-fake-user" # This is the username to attempt a login with (you can change this)
$password = "__obvious_bad_password_to_generate_auth_failures__"
$max_attempts = 30 #


# Build the connection string using Windows authentication. You don't have to touch this
$connectionString = "Server=$serverName;Database=$databaseName;Integrated Security=False;User Id=$username;Password=$password;"

$count = 0

while ($count -lt $max_attempts){
    $count++
    try {
        # Pause the script for 2 seconds to allow for processing
        Start-Sleep -Seconds 3

        # Open the connection
        $connection = New-Object System.Data.SqlClient.SqlConnection($connectionString)
        $connection.Open()
    
        # Define the SQL query to execute
        $query = "SELECT * FROM spt_monitor"
    
        # Create a command object and execute the query
        $command = New-Object System.Data.SqlClient.SqlCommand($query, $connection)
        $result = $command.ExecuteReader()
    
        # Process the query results
        while ($result.Read()) {
            Write-Host $result
        }
    
    } catch {
        # Handle any errors that occur
        Write-Host "Error: $($Error[0].Exception.Message)"
    } finally {
        # Close the connection
        if ($connection.State -eq "Open") {
            $connection.Close()
        }
    }
}

