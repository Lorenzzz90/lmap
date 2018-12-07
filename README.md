 Lmap
 =======
 
A very simplistic version of nmap written entirely in python
------
  
 ### Installation
 
 -Download and unzip the program.
 
 -From a terminal navigate into the folders and the run the command:  
 `pip install -r requirements.txt`
 
 -You will also need xvfb installed to take screenshots in headless mode, if you are running this in windws,
 you need to comment out the lines 1, 18, 19 and 42 from the screenshot.py file.
 
  (Graph-tool must to be installed locally if you want to generate a graph,   
  more info on https://graph-tool.skewed.de/)
  
 ### Usage 
 #### Basic usage
  -You can only run the program from a terminal, a GUI is not implemented yet  
  -To run the program you need administrator privileges
  
  -Navigate into the folder and execute the program with administrator privileges passing an   
    Ip Address or a network as arguments.
  
  Examples:
  
  * `sudo python3 lmap.py 192.168.1.1` 
  * `sudo python3 lmap.py 192.168.1.0/24`
  
  The program will try to enstabilish a connection on every Ip address in the network on the default well known
  ports (you can find and modify the list of the default ports in wkports.txt).  
  
  If no additional argument is passed trough the command line the program will only write a report in the 
  info.log file in the main directory.  
  #### Excel Report | --excel | -e
  For more detailed reports you can pass the -e argument which compiles an excel file at the end of the scan
  and saves it under the 'reports' subfolder.
  
  Example:
  
  * `sudo python3 lmap.py 10.10.0.0/16 -e`
  
  #### Histogram | --histogram | -h
  If you want to create an histogram which ranks the most open ports on a given network you can pass the -i
  argument, it will create a file called open_ports.svg in the main directory, you can use a web browser to
  visualize the file.
  
  Example:
  
  *`sudo python3 lmap.py 192.168.1.0/24 -i` 
  
  #### Custom ports | --ports | -p
  
  If you want to perform a scan on custom ports you can pass the -p argument and manually select the ports 
  to scan for every ip.
  
  Examples:
  
  * `sudo python3 lmap.py 192.168.1.30 -p 22` perform a scan on ip 192.168.1.30 only on port 22
  * `sudo python3 lmap.py 192.168.1.0/24 -p 22 80 443` perform a scan on the whole network on ports 22, 
  80 and 443
  * `sudo python3 lmap.py 10.0.0.0/8 - p 1-1000` perform a scan on the whole network on all the ports 
  inside the range 1 and 1000 (1, 2, 3, 4.........998, 999 1000)
  * `sudo python3 lmap.py 172.16.0.0/16 -p 22 80 100-200` perform a scan on the whole network on the ports
  22, 80 and all the port inside the range 100 and 200 (22, 80, 100, 101, 102..........199, 200) 
  
  #### Screenshots | --ports | -p
  
  You can take a screenshots on port 80 and 443 if the port is open and a service is exposed on those 
  by passing the -s argument, a screenshot will be saved in the screenshot folder with the  
  datetime-ip-port as a filename.
  If the -s argument is passed, the port 80 and 443 will be added automatically to the ports list.
  
  Examples:
  
  * `sudo python3 lmap.py 216.58.198.36 -s` if something is exposed on port 80 and 443 on the passed ip a screenshot will 
  be taken and saved inside the screenshots folder.
  
  * `sudo python3 lmap.py 192.168.1.0/24 -s` the program will try to take a screenshot on port 80 and 443 on
  every ip in the passed network
  
  #### Multithreading | --threads | -t

If you plan to scan a large network, you can pass the -t threads to make the process faster  
(default is 52 threads) every thread will take care of a single ip.

Example:

*`sudo python3 lmap.py 10.0.0.0/8 -t 80` the program will generate and use 80 threads, scanning 80 Ip 
addresses simultaneously

Disclaimer: depending on you pc specification running too many threads could results in crashes and loss
of performance 

#### Fingerprinting and basic OS Detection | --fingerprint | -f

You can perform some fingerprinting actions by passing the -f argument, the program will add ports 
22, 135, 445 and 3389 to the port list since those are common ports that are usually mutually used by 
Linux or Windows, additionally the program will craft and send six TCP packets probes and analyze the 
responses to try to detect the os installed is windows or linux.

You can also check the banners in the excel file to try to gather some additional information on the running 
os.

Additionally all the responses every ip send back is saved inside the packets folder.

Example:

* `sudo python3 192.168.1.3 -f -e` the program will try to determine the os running on the given ip and
print the result in an excel file inside the reports folder.

#### Custom ports from file | --fileports | -fp 

You can pass a custom file and do a scan on the ports contained on that file with the -fp argument,
the text inside the file must be formatted as in the wkports.txt default file, port number, a single blank space 
and a description of the port.

Examples:  

**customports.txt**  
22 SSh  
80 HTTP  
443 HTTPS  

*`sudo python3 lmap.py 10.10.10.0/24 -fp <path of the file>`

#### Combined parameters

You can conbine every other parameter describer so far to a more detailed scanning.

Examples:

* `sudo python3 lmap.py 192.168.1.0/24 -p 22 23 80 100-1000 -s -f -e -t70`   
Running the program with those parameters will test the given network using 70 threads, it will test connections on port 22, 23, 80 and all ports from 100 to 1000.  
It will also try to take screenshots and save them in the screenshots folder if it will find open the port 80 or 443.  
It will perform a fingerprinting action to try to detect an os and save al the packets inside the packets folder.  
Finally it will write an excel report and save it inside the report folder.


#### Graph | --graph | -g WORK IN PROGRESS 
This part of the program is still in development and it will be added later
  
 
 
