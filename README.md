```
FTP Server Component for ESPHome
An FTP server component for ESPHome that supports both standard FTP and FTPS (FTP over TLS) connections. This component allows you to browse and transfer files to your ESP32 device remotely.

Features
Standard FTP protocol support
FTPS (FTP over TLS) for secure connections
User authentication
File upload and download
Directory creation, listing, and navigation
File rename and delete operations
External access support through NAT/routers
Configurable passive port range
Installation
Copy the ftp_server directory to your ESPHome custom_components directory.
Add the component to your YAML configuration file.
Configuration

# Example configuration
ftp_server:
  id: my_ftp_server
  username: "admin" 
  password: "secure_password"
  root_path: "/sdcard"
  port: 21
  enable_tls: true
  
  # Your public IP address for external connections
  # ESP32 will continue to use its local IP for all other services
  external_ip: "203.0.113.42"
  
  # Port range to open on your router for passive mode
  # These ports must be forwarded to the ESP32's local IP
  passive_port_min: 50000
  passive_port_max: 50100
Configuration Variables:
Variable	Type	Required	Default	Description
username	string	Yes	-	Username for FTP authentication
password	string	Yes	-	Password for FTP authentication
root_path	string	No	/	Root directory path for FTP access
port	integer	No	21	Port for FTP service
enable_tls	boolean	No	false	Enable FTPS (FTP over TLS)
external_ip	string	No	-	Your public IP address for external connections
passive_port_min	integer	No	-	Minimum port number for passive mode
passive_port_max	integer	No	-	Maximum port number for passive mode
External Access Setup
To enable access from outside your local network:

Configure external_ip with your public IP address
Set up a range of ports for passive mode using passive_port_min and passive_port_max
Forward the FTP port (default: 21) and the passive port range to your ESP32's local IP address on your router
Enable TLS for better security when accessing over the internet
Client Usage
Connect to your FTP server using any standard FTP client like FileZilla, WinSCP, or command-line FTP clients.

For secure connections, ensure your client is set to use explicit FTPS mode.

Composant Serveur FTP pour ESPHome
Un composant serveur FTP pour ESPHome qui prend en charge les connexions FTP standard et FTPS (FTP sécurisé par TLS). Ce composant vous permet de parcourir et transférer des fichiers vers votre appareil ESP32 à distance.

Fonctionnalités
Support du protocole FTP standard
FTPS (FTP sur TLS) pour des connexions sécurisées
Authentification utilisateur
Téléchargement et upload de fichiers
Création, listage et navigation dans les répertoires
Opérations de renommage et suppression de fichiers
Support d'accès externe à travers NAT/routeurs
Plage de ports passifs configurable
Installation
Copiez le répertoire ftp_server dans votre dossier custom_components d'ESPHome.
Ajoutez le composant à votre fichier de configuration YAML.
Configuration

# Exemple de configuration
ftp_server:
  id: my_ftp_server
  username: "admin" 
  password: "mot_de_passe_securise"
  root_path: "/sdcard"
  port: 21
  enable_tls: true
  
  # Votre adresse IP publique pour les connexions externes
  # L'ESP32 continuera d'utiliser son adresse IP locale pour tous les autres services
  external_ip: "203.0.113.42"
  
  # Plage de ports à ouvrir sur votre routeur pour le mode passif
  # Ces ports doivent être redirigés vers l'adresse IP locale de l'ESP32
  passive_port_min: 50000
  passive_port_max: 50100
Variables de configuration:
Variable	Type	Requis	Défaut	Description
username	chaîne	Oui	-	Nom d'utilisateur pour l'authentification FTP
password	chaîne	Oui	-	Mot de passe pour l'authentification FTP
root_path	chaîne	Non	/	Chemin du répertoire racine pour l'accès FTP
port	entier	Non	21	Port pour le service FTP
enable_tls	booléen	Non	false	Activer FTPS (FTP sur TLS)
external_ip	chaîne	Non	-	Votre adresse IP publique pour les connexions externes
passive_port_min	entier	Non	-	Numéro de port minimum pour le mode passif
passive_port_max	entier	Non	-	Numéro de port maximum pour le mode passif
Configuration d'accès externe
Pour permettre l'accès depuis l'extérieur de votre réseau local:

Configurez external_ip avec votre adresse IP publique
Définissez une plage de ports pour le mode passif en utilisant passive_port_min et passive_port_max
Redirigez le port FTP (par défaut : 21) et la plage de ports passifs vers l'adresse IP locale de votre ESP32 sur votre routeur
Activez TLS pour une meilleure sécurité lors de l'accès via internet
Utilisation du client
Connectez-vous à votre serveur FTP en utilisant n'importe quel client FTP standard comme FileZilla, WinSCP, ou des clients FTP en ligne de commande.

Pour les connexions sécurisées, assurez-vous que votre client est configuré pour utiliser le mode FTPS explicite.
```
