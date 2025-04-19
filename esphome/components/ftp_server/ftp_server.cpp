#include "ftp_server.h"
#include "../sd_mmc_card/sd_mmc_card.h"
#include "esp_log.h"
#include <fcntl.h>
#include <dirent.h>
#include <sys/stat.h>
#include <unistd.h>
#include <chrono>
#include <ctime>
#include "esp_netif.h"
#include "esp_err.h"
#include <errno.h>
#include "esp_tls.h"
#include "mbedtls/base64.h"

namespace esphome {
namespace ftp_server {

static const char *TAG = "ftp_server";

// Certificat et clé privée pour TLS
// Ces certificats sont auto-signés et devraient être remplacés pour une utilisation en production
static const char* server_cert = 
"-----BEGIN CERTIFICATE-----\n"
"MIIDXTCCAkWgAwIBAgIJAJlc6SmPT8wKMA0GCSqGSIb3DQEBCwUAMEUxCzAJBgNV\n"
"BAYTAkFVMRMwEQYDVQQIDApTb21lLVN0YXRlMSEwHwYDVQQKDBhJbnRlcm5ldCBX\n"
"aWRnaXRzIFB0eSBMdGQwHhcNMjMxMjAxMDAwMDAwWhcNMjQxMjMxMDAwMDAwWjBF\n"
"MQswCQYDVQQGEwJBVTETMBEGA1UECAwKU29tZS1TdGF0ZTEhMB8GA1UECgwYSW50\n"
"ZXJuZXQgV2lkZ2l0cyBQdHkgTHRkMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIB\n"
"CgKCAQEAzcScDp6/yD6fSKpQodmQvkjMV7zcGA4NvFFSX9cZa56TR+EYs+Rt2Wk9\n"
"bWjjpOXAzXyuXLNUP7xSjZeXnT8B5OlcjHxP1eQPH1TNFNkGFAdK3K2c8JQl7zMq\n"
"wZKB2hVDWEYf/rE9gFO2hq0HhZ6IjCZ5my1BQeFzWrZYgoroHaOFN6OJqfhQ+paJ\n"
"M/l8tOKHp4yBwTCflw4ke1g0XyStidGtglbGT5FJ+zuCPD8ly7Fn6D0Zu5m7LRhQ\n"
"BtWj+26KRyG8GT+NnuCYER9O+uRH5fYWQvApe8ZSgbP7jZYJQHXqQ9xRfnuHUH5E\n"
"QZhFnoh4CtxRFG8WEEMVXHswcQIDAQABo1AwTjAdBgNVHQ4EFgQUz5oKlvpOQSzs\n"
"KH4/gQMjRxCBnXQwHwYDVR0jBBgwFoAUz5oKlvpOQSzs\n"
"KH4/gQMjRxCBnXQwDAYDVR0TBAUwAwEB/zANBgkqhkiG9w0BAQsFAAOCAQEAFmYA\n"
"bP8Bj5QcIYj6iQfHFH4Z+mKxTn9+Y7Jc+a7u9xLB9p4T8CeEKgAzgwdkKZ/V2Ot9\n"
"CipJQfMOJ3m4pTCpT4MLRcJLrfC1/cKHRGCF4PjL6hAmJGdnYLvc3KFxjCFFCpBh\n"
"wWcmM48O3+Dt9+W+jLh3S3E0fmCIPYCdzPJGoZUXTnxfp8AgdSPDxbEMqSjJ+WBE\n"
"TA6VwrD4xIXa6I2K1A4Jv6UaKjIpKgvg3qZkGYSvHqMZwELCWz+WQZRMHRGHKzOU\n"
"GQPXUYXa91bJ2pGvfbWRwGTWWZLiKwmZQDZDpFOZfI+q3xfS5K9RL6oKKj6tFEfg\n"
"xK0khdLO2JzTWRZ3jQ==\n"
"-----END CERTIFICATE-----\n";

static const char* server_key = 
"-----BEGIN PRIVATE KEY-----\n"
"MIIEvgIBADANBgkqhkiG9w0BAQEFAASCBKgwggSkAgEAAoIBAQDNxJwOnr/IPp9I\n"
"qlCh2ZC+SMxXvNwYDg28UVJf1xlrnpNH4Riz5G3ZaT1taOOk5cDNfK5cs1Q/vFKN\n"
"l5edPwHk6VyMfE/V5A8fVM0U2QYUB0rcrZzwlCXvMyrBkoHaFUNYRh/+sT2AU7aG\n"
"rQeFnoiMJnmbLUFB4XNatliCiugdo4U3o4mp+FD6lokz+Xy04oenjIHBMJ+XDiR7\n"
"WDRfJK2J0a2CVsZPkUn7O4I8PyXLsWfoPRm7mbstGFAG1aP7bopHIbwZP42e4JgR\n"
"H0765Efl9hZC8Cl7xlKBs/uNlglAdeqD3FF+e4dQfkRBmEWeiHgK3FEUbxYQQxVc\n"
"ezBxAgMBAAECggEADVwgHs94p1hWM16GUj9gxX9BC2I/mN/JlXoS4TthDNUJDiFn\n"
"2b9p5V2l8wPg5U9qEpwZCFzQGiU67pZZEVxz5AQVzA3JXBxgUEE9MEJlIGcbF5OB\n"
"VOZkJYdKMZRFp8D+MEQUHKhBvHJxlxGaKTNDlp1j0R6FXfV48IfXHjGCMp/GEBSA\n"
"E5L4UN3h0wP4+2BHAsLWZp3dOlWBbN8YXK9O+oBJqE0YlFrHX8ibtvVJ7R2ID3cj\n"
"A55Lqi4j2mdOHzQBNzXDWg8I26vwdlLl5m0R2hJ4GkRPBgkeXlowMP/s5ItBQEzq\n"
"RdEgx3NZJYiyZ8RiDGHiZTqc03SDk5uOmzeOnZngAQKBgQDzc3KKvdkE3z3uCBH/\n"
"+jJLJa7XEGIvttmx8btdcIcbLU3QmJ8hXsJK7nU3cWXX97yELbvWKyEoP7JbWCGi\n"
"zVmEpbBvkfILCZCaGdYq3DrVQ2F8VuUGVlTdWS5SMaKHXHQY+EGFXnZG34znT0er\n"
"MwZuhuRR4NWDtZcHrGgc6LfEwQKBgQDYRH15C2rkgWG5V1tZQBwuJ0rqdTtEkEvr\n"
"WrYvJM9dhpZT5zRYzKnkn8D3G3/oB9vX9tY+prmKz/3/vCPvY6Od4DiX/jJYK5Qz\n"
"8FjOcHAp4u0GKpS8c+993MH7Sqj2xOUjMzJmQBX1ZJLjYbZ3d/SYKiO6d+emdv+Y\n"
"S3h0Y9HaMQKBgQDFIgApXX0oivIYUQcOYjKPMKl+wRR6gR4LbZIA+KaUTKc4IkpR\n"
"j85GdCyVWh/Y8RkrNRzNAQtRxZcBayZJ6QkL5BKncgizFd2gpK0N+3JBUYT7GrA7\n"
"3KAGhUDlcXZ0vVNHMCF6SwO0dE7YIJhL5JX4bks/vdV3gRlG2unscrH6QQKBgQDB\n"
"FLyH3SMC76ByR4zGWK27e3vwDL7a0LKnMKXULwTJzqrT1tpH3hGQQPc0QwURtTJP\n"
"ov9Wm7uN8RGYFnhkesuU2nyc/iT83VJbB54rD7ks9EZE1vlwSV9PNZ80WBgOi0v9\n"
"qFM4cl4NpFrQvLRXbe5E5lK5JuXVP7b34DvoFYePYQKBgF9RFxGQkwyaT+RKHMm4\n"
"HS4ZYCic0bFl1P1+EHaHzCKP7pxZjDOGaCIOg1W7U4pA2CQXzdhLywlxhNBYhP1k\n"
"CdN+E9iNYOznvdKUT1/qWbrrPatVxJXrZJxkZJJJBwwgQRdO71KwNiFmP2R2RSFT\n"
"QOx1pZmQ5LXmKXwZKUQJbHVG\n"
"-----END PRIVATE KEY-----\n";

FTPServer::FTPServer() : 
  ftp_server_socket_(-1),
  passive_data_socket_(-1),
  passive_data_port_(-1),
  passive_mode_enabled_(false),
  tls_enabled_(false),
  rename_from_("") {}

std::string normalize_path(const std::string& base_path, const std::string& path) {
  std::string result;
  
  if (path.empty() || path == ".") {
    return base_path;
  }
  
  if (path[0] == '/') {
    if (path == "/") {
      return base_path;
    }
    std::string clean_path = path;
    if (base_path.back() == '/' && path[0] == '/') {
      clean_path = path.substr(1);
    }
    result = base_path + clean_path;
  } else {
    if (base_path.back() == '/') {
      result = base_path + path;
    } else {
      result = base_path + "/" + path;
    }
  }
  
  ESP_LOGD(TAG, "Normalized path: %s (from base: %s, request: %s)", 
           result.c_str(), base_path.c_str(), path.c_str());
  
  return result;
}

void FTPServer::setup() {
  ESP_LOGI(TAG, "Setting up FTP server...");

  // Initialize TLS configuration
  tls_cfg_ = {
      .alpn_protos = NULL,
      .cacert_buf = NULL,
      .cacert_bytes = 0,
      .cert_buf = (const unsigned char*)server_cert,
      .cert_bytes = strlen(server_cert) + 1,
      .clientcert_buf = NULL,
      .clientcert_bytes = 0,
      .clientkey_buf = NULL,
      .clientkey_bytes = 0,
      .common_name = NULL,
      .keep_alive_cfg = NULL,
      .non_block = false,
      .psk_hint_key = NULL,
      .skip_common_name = false,
      .timeout_ms = 10000,
      .use_global_ca_store = false,
      .userkey_buf = (const unsigned char*)server_key,
      .userkey_bytes = strlen(server_key) + 1,
  };

  if (root_path_.empty()) {
    root_path_ = "/";
  }
  
  if (root_path_.back() != '/') {
    root_path_ += '/';
  }

  DIR *dir = opendir(root_path_.c_str());
  if (dir == nullptr) {
    ESP_LOGE(TAG, "Root directory %s does not exist or is not accessible (errno: %d)", 
             root_path_.c_str(), errno);
    if (mkdir(root_path_.c_str(), 0755) != 0) {
      ESP_LOGE(TAG, "Failed to create root directory %s (errno: %d)", 
               root_path_.c_str(), errno);
    } else {
      ESP_LOGI(TAG, "Created root directory %s", root_path_.c_str());
      dir = opendir(root_path_.c_str());
    }
  }
  
  if (dir != nullptr) {
    closedir(dir);
  } else {
    ESP_LOGE(TAG, "Root directory %s still not accessible after creation attempt", 
             root_path_.c_str());
  }

  ftp_server_socket_ = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
  if (ftp_server_socket_ < 0) {
    ESP_LOGE(TAG, "Failed to create FTP server socket (errno: %d)", errno);
    return;
  }

  int opt = 1;
  if (setsockopt(ftp_server_socket_, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt)) < 0) {
    ESP_LOGE(TAG, "Failed to set socket options (errno: %d)", errno);
    close(ftp_server_socket_);
    ftp_server_socket_ = -1;
    return;
  }

  struct sockaddr_in server_addr;
  memset(&server_addr, 0, sizeof(server_addr));
  server_addr.sin_family = AF_INET;
  server_addr.sin_port = htons(port_);
  server_addr.sin_addr.s_addr = htonl(INADDR_ANY);
  if (bind(ftp_server_socket_, (struct sockaddr *)&server_addr, sizeof(server_addr)) < 0) {
    ESP_LOGE(TAG, "Failed to bind FTP server socket (errno: %d)", errno);
    close(ftp_server_socket_);
    ftp_server_socket_ = -1;
    return;
  }

  if (listen(ftp_server_socket_, 5) < 0) {
    ESP_LOGE(TAG, "Failed to listen on FTP server socket (errno: %d)", errno);
    close(ftp_server_socket_);
    ftp_server_socket_ = -1;
    return;
  }

  fcntl(ftp_server_socket_, F_SETFL, O_NONBLOCK);

  ESP_LOGI(TAG, "FTP server started on port %d", port_);
  ESP_LOGI(TAG, "Root directory: %s", root_path_.c_str());
  ESP_LOGI(TAG, "TLS support: %s", enable_tls_ ? "enabled" : "disabled");
  current_path_ = root_path_;
}

void FTPServer::loop() {
  handle_new_clients();
  for (size_t i = 0; i < client_sockets_.size(); i++) {
    handle_ftp_client(client_sockets_[i], i);
  }
}

void FTPServer::dump_config() {
  ESP_LOGI(TAG, "FTP Server:");
  ESP_LOGI(TAG, "  Port: %d", port_);
  ESP_LOGI(TAG, "  Root Path: %s", root_path_.c_str());
  ESP_LOGI(TAG, "  Username: %s", username_.c_str());
  ESP_LOGI(TAG, "  TLS: %s", enable_tls_ ? "enabled" : "disabled");
  ESP_LOGI(TAG, "  Server status: %s", is_running() ? "Running" : "Not running");
}

void FTPServer::handle_new_clients() {
  struct sockaddr_in client_addr;
  socklen_t client_len = sizeof(client_addr);
  int client_socket = accept(ftp_server_socket_, (struct sockaddr *)&client_addr, &client_len);
  if (client_socket >= 0) {
    fcntl(client_socket, F_SETFL, O_NONBLOCK);
    char client_ip[INET_ADDRSTRLEN];
    inet_ntop(AF_INET, &(client_addr.sin_addr), client_ip, INET_ADDRSTRLEN);
    ESP_LOGI(TAG, "New FTP client connected from %s:%d", client_ip, ntohs(client_addr.sin_port));
    
    // Add the client to our lists
    client_sockets_.push_back(client_socket);
    client_states_.push_back(FTP_WAIT_LOGIN);
    client_usernames_.push_back("");
    client_current_paths_.push_back(root_path_);
    client_tls_contexts_.push_back(nullptr);
    client_secure_data_.push_back(false);
    
    send_response(client_socket, client_sockets_.size() - 1, 220, "Welcome to ESPHome FTP Server. Use AUTH TLS for secure connection.");
  }
}

void FTPServer::handle_ftp_client(int client_socket, size_t client_index) {
  char buffer[512];
  bool is_tls = client_tls_contexts_[client_index] != nullptr;
  
  int len;
  if (is_tls) {
    len = esp_tls_conn_read(client_tls_contexts_[client_index], buffer, sizeof(buffer) - 1);
    if (len < 0 && len != MBEDTLS_ERR_SSL_WANT_READ) {
      ESP_LOGE(TAG, "TLS read error: %d", len);
      close_client_connection(client_index);
      return;
    }
  } else {
    len = recv(client_socket, buffer, sizeof(buffer) - 1, MSG_DONTWAIT);
  }
  
  if (len > 0) {
    buffer[len] = '\0';
    std::string command(buffer);
    process_command(client_socket, client_index, command);
  } else if (len == 0 || (len < 0 && errno != EWOULDBLOCK && errno != EAGAIN)) {
    ESP_LOGI(TAG, "FTP client disconnected");
    close_client_connection(client_index);
  }
}

void FTPServer::close_client_connection(size_t client_index) {
  if (client_index >= client_sockets_.size()) {
    return;
  }
  
  int client_socket = client_sockets_[client_index];
  
  // If using TLS, clean up TLS context
  if (client_tls_contexts_[client_index] != nullptr) {
    esp_tls_conn_destroy(client_tls_contexts_[client_index]);
  }
  
  close(client_socket);
  
  // Remove this client from our tracking lists
  client_sockets_.erase(client_sockets_.begin() + client_index);
  client_states_.erase(client_states_.begin() + client_index);
  client_usernames_.erase(client_usernames_.begin() + client_index);
  client_current_paths_.erase(client_current_paths_.begin() + client_index);
  client_tls_contexts_.erase(client_tls_contexts_.begin() + client_index);
  client_secure_data_.erase(client_secure_data_.begin() + client_index);
}

void FTPServer::process_command(int client_socket, size_t client_index, const std::string& command) {
  ESP_LOGI(TAG, "FTP command: %s", command.c_str());
  std::string cmd_str = command;
  size_t pos = cmd_str.find_first_of("\r\n");
  if (pos != std::string::npos) {
    cmd_str = cmd_str.substr(0, pos);
  }

  if (cmd_str.find("AUTH") == 0) {
    std::string auth_type = cmd_str.substr(5);
    if (auth_type == "TLS" && enable_tls_) {
      send_response(client_socket, client_index, 234, "AUTH TLS successful");
      
      // Set up TLS context for this client
      esp_tls_t* tls = esp_tls_init();
      if (tls == nullptr) {
        ESP_LOGE(TAG, "Failed to initialize TLS");
        return;
      }
      
      int ret = esp_tls_server_session_create(&tls_cfg_, client_socket, tls);
      if (ret != ESP_OK) {
        ESP_LOGE(TAG, "Failed to create TLS session: %d", ret);
        esp_tls_conn_destroy(tls);
        return;
      }
      
      client_tls_contexts_[client_index] = tls;
    } else {
      send_response(client_socket, client_index, 502, "AUTH not supported");
    }
  } else if (cmd_str.find("PBSZ") == 0) {
    if (client_tls_contexts_[client_index] != nullptr) {
      // PBSZ 0 is required for TLS
      send_response(client_socket, client_index, 200, "PBSZ=0");
    } else {
      send_response(client_socket, client_index, 503, "TLS connection not established");
    }
  } else if (cmd_str.find("PROT") == 0) {
    if (client_tls_contexts_[client_index] != nullptr) {
      std::string prot_level = cmd_str.substr(5);
      if (prot_level == "P") {
        client_secure_data_[client_index] = true;
        send_response(client_socket, client_index, 200, "Protection set to Private");
      } else if (prot_level == "C") {
        client_secure_data_[client_index] = false;
        send_response(client_socket, client_index, 200, "Protection set to Clear");
      } else {
        send_response(client_socket, client_index, 504, "PROT level not supported");
      }
    } else {
      send_response(client_socket, client_index, 503, "TLS connection not established");
    }
  } else if (cmd_str.find("USER") == 0) {
    std::string username = cmd_str.substr(5);
    client_usernames_[client_index] = username;
    send_response(client_socket, client_index, 331, "Password required for " + username);
  } else if (cmd_str.find("PASS") == 0) {
    std::string password = cmd_str.substr(5);
    if (authenticate(client_usernames_[client_index], password)) {
      client_states_[client_index] = FTP_LOGGED_IN;
      send_response(client_socket, client_index, 230, "Login successful");
    } else {
      send_response(client_socket, client_index, 530, "Login incorrect");
    }
  } else if (client_states_[client_index] != FTP_LOGGED_IN) {
    send_response(client_socket, client_index, 530, "Not logged in");
  } else if (cmd_str.find("SYST") == 0) {
    send_response(client_socket, client_index, 215, "UNIX Type: L8");
  } else if (cmd_str.find("FEAT") == 0) {
    send_response(client_socket, client_index, 211, "Features:");
    send_response(client_socket, client_index, 211, " SIZE");
    send_response(client_socket, client_index, 211, " MDTM");
    if (enable_tls_) {
      send_response(client_socket, client_index, 211, " AUTH TLS");
      send_response(client_socket, client_index, 211, " PROT");
      send_response(client_socket, client_index, 211, " PBSZ");
    }
    send_response(client_socket, client_index, 211, "End");
  } else if (cmd_str.find("TYPE") == 0) {
    send_response(client_socket, client_index, 200, "Type set to " + cmd_str.substr(5));
  } else if (cmd_str.find("PWD") == 0) {
    std::string current_path = client_current_paths_[client_index];
    std::string relative_path = "/";
    if (current_path.length() > root_path_.length()) {
      relative_path = current_path.substr(root_path_.length() - 1);
    }
    send_response(client_socket, client_index, 257, "\"" + relative_path + "\" is current directory");
  } else if (cmd_str.find("CWD") == 0) {
    std::string path = cmd_str.substr(4);
    size_t first_non_space = path.find_first_not_of(" \t");
    if (first_non_space != std::string::npos) {
      path = path.substr(first_non_space);
    }
    
    if (path.empty()) {
      send_response(client_socket, client_index, 550, "Failed to change directory - path is empty");
    } else {
      std::string current_path = client_current_paths_[client_index];
      std::string full_path;
      
      if (path == "/") {
        full_path = root_path_;
      } else {
        full_path = normalize_path(current_path, path);
      }
      
      ESP_LOGI(TAG, "Attempting to change directory to: %s", full_path.c_str());
      
      DIR *dir = opendir(full_path.c_str());
      if (dir != nullptr) {
        closedir(dir);
        client_current_paths_[client_index] = full_path;
        send_response(client_socket, client_index, 250, "Directory successfully changed");
      } else {
        ESP_LOGE(TAG, "Failed to open directory: %s (errno: %d)", full_path.c_str(), errno);
        send_response(client_socket, client_index, 550, "Failed to change directory");
      }
    }
  } else if (cmd_str.find("CDUP") == 0) {
    std::string current = client_current_paths_[client_index];
    
    if (current == root_path_ || current.length() <= root_path_.length()) {
      send_response(client_socket, client_index, 250, "Already at root directory");
      return;
    }
    
    size_t pos = current.find_last_of('/');
    if (pos != std::string::npos && current.length() > 1) {
      if (pos == current.length() - 1) {
        std::string temp = current.substr(0, pos);
        pos = temp.find_last_of('/');
      }
      
      if (pos != std::string::npos) {
        std::string parent_dir = current.substr(0, pos + 1);
        
        if (parent_dir.length() >= root_path_.length()) {
          client_current_paths_[client_index] = parent_dir;
          send_response(client_socket, client_index, 250, "Directory successfully changed");
        } else {
          client_current_paths_[client_index] = root_path_;
          send_response(client_socket, client_index, 250, "Directory changed to root");
        }
      } else {
        send_response(client_socket, client_index, 550, "Failed to change directory");
      }
    } else {
      send_response(client_socket, client_index, 550, "Failed to change directory");
    }
  } else if (cmd_str.find("PASV") == 0) {
    if (start_passive_mode(client_socket, client_index)) {
      passive_mode_enabled_ = true;
    } else {
      send_response(client_socket, client_index, 425, "Can't open passive connection");
    }
  } else if (cmd_str.find("LIST") == 0 || cmd_str.find("NLST") == 0) {
    std::string path_arg = "";
    std::string cmd_type = cmd_str.substr(0, 4);
    
    if (cmd_str.length() > 5) {
      path_arg = cmd_str.substr(5);
      size_t first_non_space = path_arg.find_first_not_of(" \t");
      if (first_non_space != std::string::npos) {
        path_arg = path_arg.substr(first_non_space);
      }
    }
    
    std::string list_path;
    if (path_arg.empty() || path_arg == ".") {
      list_path = client_current_paths_[client_index];
    } else {
      list_path = normalize_path(client_current_paths_[client_index], path_arg);
    }
    
    ESP_LOGI(TAG, "Listing directory: %s", list_path.c_str());
    send_response(client_socket, client_index, 150, "Opening ASCII mode data connection for file list");
    
    if (cmd_type == "LIST") {
      list_directory(client_socket, client_index, list_path);
    } else {
      list_names(client_socket, client_index, list_path);
    }
  } else if (cmd_str.find("STOR") == 0) {
    std::string filename = cmd_str.substr(5);
    size_t first_non_space = filename.find_first_not_of(" \t");
    if (first_non_space != std::string::npos) {
      filename = filename.substr(first_non_space);
    }
    
    std::string full_path = normalize_path(client_current_paths_[client_index], filename);
    ESP_LOGI(TAG, "Starting file upload to: %s", full_path.c_str());
    send_response(client_socket, client_index, 150, "Opening connection for file upload");
    start_file_upload(client_socket, client_index, full_path);
  } else if (cmd_str.find("RETR") == 0) {
    std::string filename = cmd_str.substr(5);
    size_t first_non_space = filename.find_first_not_of(" \t");
    if (first_non_space != std::string::npos) {
      filename = filename.substr(first_non_space);
    }
    
    std::string full_path = normalize_path(client_current_paths_[client_index], filename);
    ESP_LOGI(TAG, "Starting file download from: %s", full_path.c_str());
    
    struct stat file_stat;
    if (stat(full_path.c_str(), &file_stat) == 0) {
      if (S_ISREG(file_stat.st_mode)) {
        std::string size_msg = "Opening connection for file download (" +
                              std::to_string(file_stat.st_size) + " bytes)";
        send_response(client_socket, client_index, 150, size_msg);
        start_file_download(client_socket, client_index, full_path);
      } else {
        send_response(client_socket, client_index, 550, "Not a regular file");
      }
    } else {
      ESP_LOGE(TAG, "File not found: %s (errno: %d)", full_path.c_str(), errno);
      send_response(client_socket, client_index, 550, "File not found");
    }
  } else if (cmd_str.find("DELE") == 0) {
    std::string filename = cmd_str.substr(5);
    size_t first_non_space = filename.find_first_not_of(" \t");
    if (first_non_space != std::string::npos) {
      filename = filename.substr(first_non_space);
    }
    
    std::string full_path = normalize_path(client_current_paths_[client_index], filename);
    ESP_LOGI(TAG, "Deleting file: %s", full_path.c_str());
    
    if (unlink(full_path.c_str()) == 0) {
      send_response(client_socket, client_index, 250, "File deleted successfully");
    } else {
      ESP_LOGE(TAG, "Failed to delete file: %s (errno: %d)", full_path.c_str(), errno);
      send_response(client_socket, client_index, 550, "Failed to delete file");
    }
  } else if (cmd_str.find("MKD") == 0) {
    std::string dirname = cmd_str.substr(4);
    size_t first_non_space = dirname.find_first_not_of(" \t");
    if (first_non_space != std::string::npos) {
      dirname = dirname.substr(first_non_space);
    }
    
    std::string full_path = normalize_path(client_current_paths_[client_index], dirname);
    ESP_LOGI(TAG, "Creating directory: %s", full_path.c_str());
    
    if (mkdir(full_path.c_str(), 0755) == 0) {
      send_response(client_socket, client_index, 257, "Directory created");
    } else {
      ESP_LOGE(TAG, "Failed to create directory: %s (errno: %d)", full_path.c_str(), errno);
      send_response(client_socket, client_index, 550, "Failed to create directory");
    }
  } else if (cmd_str.find("RMD") == 0) {
    std::string dirname = cmd_str.substr(4);
    size_t first_non_space = dirname.find_first_not_of(" \t");
    if (first_non_space != std::string::npos) {
      dirname = dirname.substr(first_non_space);
    }
    
    std::string full_path = normalize_path(client_current_paths_[client_index], dirname);
    ESP_LOGI(TAG, "Removing directory: %s", full_path.c_str());
    
    if (rmdir(full_path.c_str()) == 0) {
      send_response(client_socket, client_index, 250, "Directory removed");
    } else {
      ESP_LOGE(TAG, "Failed to remove directory: %s (errno: %d)", full_path.c_str(), errno);
      send_response(client_socket, client_index, 550, "Failed to remove directory");
    }
  } else if (cmd_str.find("RNFR") == 0) {
    std::string filename = cmd_str.substr(5);
    size_t first_non_space = filename.find_first_not_of(" \t");
    if (first_non_space != std::string::npos) {
      filename = filename.substr(first_non_space);
    }
    
    rename_from_ = normalize_path(client_current_paths_[client_index], filename);
    struct stat file_stat;
    if (stat(rename_from_.c_str(), &file_stat) == 0) {
      send_response(client_socket, client_index, 350, "Ready for RNTO");
    } else {
      ESP_LOGE(TAG, "File not found for rename: %s (errno: %d)", rename_from_.c_str(), errno);
      send_response(client_socket, client_index, 550, "File not found");
      rename_from_ = "";
    }
  } else if (cmd_str.find("RNTO") == 0) {
    if (rename_from_.empty()) {
      send_response(client_socket, client_index, 503, "RNFR required first");
    } else {
      std::string filename = cmd_str.substr(5);
      size_t first_non_space = filename.find_first_not_of(" \t");
      if (first_non_space != std::string::npos) {
        filename = filename.substr(first_non_space);
      }
      
      std::string rename_to = normalize_path(client_current_paths_[client_index], filename);
      ESP_LOGI(TAG, "Renaming from %s to %s", rename_from_.c_str(), rename_to.c_str());
      
      if (rename(rename_from_.c_str(), rename_to.c_str()) == 0) {
        send_response(client_socket, client_index, 250, "Rename successful");
      } else {
        ESP_LOGE(TAG, "Failed to rename: %s -> %s (errno: %d)", 
                 rename_from_.c_str(), rename_to.c_str(), errno);
        send_response(client_socket, client_index, 550, "Rename failed");
      }
      rename_from_ = "";
    }
  } else if (cmd_str.find("SIZE") == 0) {
    std::string filename = cmd_str.substr(5);
    size_t first_non_space = filename.find_first_not_of(" \t");
    if (first_non_space != std::string::npos) {
      filename = filename.substr(first_non_space);
    }
    
    std::string full_path = normalize_path(client_current_paths_[client_index], filename);
    struct stat file_stat;
    if (stat(full_path.c_str(), &file_stat) == 0 && S_ISREG(file_stat.st_mode)) {
      send_response(client_socket, client_index, 213, std::to_string(file_stat.st_size));
    } else {
      send_response(client_socket, client_index, 550, "File not found or not a regular file");
    }
  } else if (cmd_str.find("MDTM") == 0) {
    std::string filename = cmd_str.substr(5);
    size_t first_non_space = filename.find_first_not_of(" \t");
    if (first_non_space != std::string::npos) {
      filename = filename.substr(first_non_space);
    }
    
    std::string full_path = normalize_path(client_current_paths_[client_index], filename);
    struct stat file_stat;
    if (stat(full_path.c_str(), &file_stat) == 0) {
      char mdtm_str[15];
      struct tm *tm_info = gmtime(&file_stat.st_mtime);
      strftime(mdtm_str, sizeof(mdtm_str), "%Y%m%d%H%M%S", tm_info);
      send_response(client_socket, client_index, 213, mdtm_str);
    } else {
      send_response(client_socket, client_index, 550, "File not found");
    }
  } else if (cmd_str.find("NOOP") == 0) {
    send_response(client_socket, client_index, 200, "NOOP command successful");
  } else if (cmd_str.find("QUIT") == 0) {
    send_response(client_socket, client_index, 221, "Goodbye");
    close_client_connection(client_index);
  } else {
    send_response(client_socket, client_index, 502, "Command not implemented");
  }
}

void FTPServer::send_response(int client_socket, size_t client_index, int code, const std::string& message) {
  std::string response = std::to_string(code) + " " + message + "\r\n";
  
  if (client_tls_contexts_[client_index] != nullptr) {
    // Send over TLS
    esp_tls_conn_write(client_tls_contexts_[client_index], response.c_str(), response.length());
  } else {
    // Send over plain socket
    send(client_socket, response.c_str(), response.length(), 0);
  }
  
  ESP_LOGD(TAG, "Sent: %s", response.c_str());
}

bool FTPServer::authenticate(const std::string& username, const std::string& password) {
  return username == username_ && password == password_;
}

bool FTPServer::start_passive_mode(int client_socket, size_t client_index) {
  if (passive_data_socket_ != -1) {
    close(passive_data_socket_);
    passive_data_socket_ = -1;
  }

  passive_data_socket_ = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
  if (passive_data_socket_ < 0) {
    ESP_LOGE(TAG, "Failed to create passive data socket (errno: %d)", errno);
    return false;
  }

  int opt = 1;
  if (setsockopt(passive_data_socket_, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt)) < 0) {
    ESP_LOGE(TAG, "Failed to set socket options for passive mode (errno: %d)", errno);
    close(passive_data_socket_);
    passive_data_socket_ = -1;
    return false;
  }

  struct sockaddr_in data_addr;
  memset(&data_addr, 0, sizeof(data_addr));
  data_addr.sin_family = AF_INET;
  data_addr.sin_addr.s_addr = htonl(INADDR_ANY);
  
  // If external passive port range is configured, use that
  if (passive_port_min_ > 0 && passive_port_max_ > passive_port_min_) {
    static uint16_t next_port = passive_port_min_;
    passive_data_port_ = next_port++;
    if (next_port > passive_port_max_) {
      next_port = passive_port_min_;
    }
    data_addr.sin_port = htons(passive_data_port_);
  } else {
    // Otherwise let the OS choose a port
    data_addr.sin_port = htons(0);
  }

  if (bind(passive_data_socket_, (struct sockaddr *)&data_addr, sizeof(data_addr)) < 0) {
    ESP_LOGE(TAG, "Failed to bind passive data socket (errno: %d)", errno);
    close(passive_data_socket_);
    passive_data_socket_ = -1;
    return false;
  }

  if (listen(passive_data_socket_, 1) < 0) {
    ESP_LOGE(TAG, "Failed to listen on passive data socket (errno: %d)", errno);
    close(passive_data_socket_);
    passive_data_socket_ = -1;
    return false;
  }

  struct sockaddr_in sin;
  socklen_t len = sizeof(sin);
  if (getsockname(passive_data_socket_, (struct sockaddr *)&sin, &len) < 0) {
    ESP_LOGE(TAG, "Failed to get socket name (errno: %d)", errno);
    close(passive_data_socket_);
    passive_data_socket_ = -1;
    return false;
  }

  passive_data_port_ = ntohs(sin.sin_port);

  // Use external IP if configured, otherwise get the local IP
  uint32_t ip;
  if (!external_ip_.empty()) {
    struct in_addr addr;
    inet_aton(external_ip_.c_str(), &addr);
    ip = ntohl(addr.s_addr);
  } else {
    esp_netif_t *netif = esp_netif_get_default_netif();
    if (netif == nullptr) {
      ESP_LOGE(TAG, "Failed to get default netif");
      close(passive_data_socket_);
      passive_data_socket_ = -1;
      return false;
    }
    esp_netif_ip_info_t ip_info;
    if (esp_netif_get_ip_info(netif, &ip_info) != ESP_OK) {
      ESP_LOGE(TAG, "Failed to get IP info");
      close(passive_data_socket_);
      passive_data_socket_ = -1;
      return false;
    }
    ip = ntohl(ip_info.ip.addr);
  }

  std::string response = "Entering Passive Mode (" +
                        std::to_string((ip >> 24) & 0xFF) + "," +
                        std::to_string((ip >> 16) & 0xFF) + "," +
                        std::to_string((ip >> 8) & 0xFF) + "," +
                        std::to_string(ip & 0xFF) + "," +
                        std::to_string(passive_data_port_ >> 8) + "," +
                        std::to_string(passive_data_port_ & 0xFF) + ")";

  send_response(client_socket, client_index, 227, response);
  return true;
}

int FTPServer::open_data_connection(int client_socket, size_t client_index) {
  if (passive_data_socket_ == -1) {
    return -1;
  }

  struct timeval tv;
  tv.tv_sec = 5;
  tv.tv_usec = 0;

  fd_set readfds;
  FD_ZERO(&readfds);
  FD_SET(passive_data_socket_, &readfds);

  int ret = select(passive_data_socket_ + 1, &readfds, nullptr, nullptr, &tv);
  if (ret <= 0) {
    return -1;
  }

  struct sockaddr_in client_addr;
  socklen_t client_len = sizeof(client_addr);
  int data_socket = accept(passive_data_socket_, (struct sockaddr *)&client_addr, &client_len);

  if (data_socket < 0) {
    return -1;
  }

  int flags = fcntl(data_socket, F_GETFL, 0);
  fcntl(data_socket, F_SETFL, flags & ~O_NONBLOCK);
  
  // If the client is using secure data transfers, wrap this data socket with TLS
  if (client_secure_data_[client_index] && enable_tls_) {
    ESP_LOGI(TAG, "Securing data connection with TLS");
    
    esp_tls_t* tls_data = esp_tls_init();
    if (tls_data == nullptr) {
      ESP_LOGE(TAG, "Failed to initialize TLS for data connection");
      close(data_socket);
      return -1;
    }
    
    int ret = esp_tls_server_session_create(&tls_cfg_, data_socket, tls_data);
    if (ret != ESP_OK) {
      ESP_LOGE(TAG, "Failed to create TLS session for data: %d", ret);
      esp_tls_conn_destroy(tls_data);
      close(data_socket);
      return -1;
    }
    
    // Store the TLS context for data connection
    data_tls_context_ = tls_data;
    return data_socket;
  }

  return data_socket;
}

void FTPServer::close_data_connection(int client_socket) {
  // Clean up TLS context for data if it exists
  if (data_tls_context_ != nullptr) {
    esp_tls_conn_destroy(data_tls_context_);
    data_tls_context_ = nullptr;
  }
  
  if (passive_data_socket_ != -1) {
    close(passive_data_socket_);
    passive_data_socket_ = -1;
    passive_data_port_ = -1;
    passive_mode_enabled_ = false;
  }
}

void FTPServer::list_directory(int client_socket, size_t client_index, const std::string& path) {
  int data_socket = open_data_connection(client_socket, client_index);
  if (data_socket < 0) {
    send_response(client_socket, client_index, 425, "Can't open data connection");
    return;
  }

  DIR *dir = opendir(path.c_str());
  if (dir == nullptr) {
    close(data_socket);
    close_data_connection(client_socket);
    send_response(client_socket, client_index, 550, "Failed to open directory");
    return;
  }

  struct dirent *entry;
  while ((entry = readdir(dir)) != nullptr) {
    std::string entry_name = entry->d_name;
    if (entry_name == "." || entry_name == "..") {
      continue;
    }

    std::string full_path = path;
    if (path.back() != '/') {
      full_path += '/';
    }
    full_path += entry_name;
    
    struct stat entry_stat;
    if (stat(full_path.c_str(), &entry_stat) == 0) {
      char time_str[80];
      strftime(time_str, sizeof(time_str), "%b %d %H:%M", localtime(&entry_stat.st_mtime));
      
      char perm_str[11] = "----------";
      if (S_ISDIR(entry_stat.st_mode)) perm_str[0] = 'd';
      if (entry_stat.st_mode & S_IRUSR) perm_str[1] = 'r';
      if (entry_stat.st_mode & S_IWUSR) perm_str[2] = 'w';
      if (entry_stat.st_mode & S_IXUSR) perm_str[3] = 'x';
      if (entry_stat.st_mode & S_IRGRP) perm_str[4] = 'r';
      if (entry_stat.st_mode & S_IWGRP) perm_str[5] = 'w';
      if (entry_stat.st_mode & S_IXGRP) perm_str[6] = 'x';
      if (entry_stat.st_mode & S_IROTH) perm_str[7] = 'r';
      if (entry_stat.st_mode & S_IWOTH) perm_str[8] = 'w';
      if (entry_stat.st_mode & S_IXOTH) perm_str[9] = 'x';

      char list_item[512];
      snprintf(list_item, sizeof(list_item),
               "%s 1 root root %8ld %s %s\r\n",
               perm_str, (long)entry_stat.st_size, time_str, entry_name.c_str());
      
      // Send data through TLS if secured data connection is used
      if (data_tls_context_ != nullptr) {
        esp_tls_conn_write(data_tls_context_, list_item, strlen(list_item));
      } else {
        send(data_socket, list_item, strlen(list_item), 0);
      }
    }
  }

  closedir(dir);
  close(data_socket);
  close_data_connection(client_socket);
  send_response(client_socket, client_index, 226, "Directory send OK");
}

void FTPServer::list_names(int client_socket, size_t client_index, const std::string& path) {
  int data_socket = open_data_connection(client_socket, client_index);
  if (data_socket < 0) {
    send_response(client_socket, client_index, 425, "Can't open data connection");
    return;
  }

  DIR *dir = opendir(path.c_str());
  if (dir == nullptr) {
    close(data_socket);
    close_data_connection(client_socket);
    send_response(client_socket, client_index, 550, "Failed to open directory");
    return;
  }

  struct dirent *entry;
  while ((entry = readdir(dir)) != nullptr) {
    std::string entry_name = entry->d_name;
    if (entry_name == "." || entry_name == "..") {
      continue;
    }

    std::string full_path = path;
    if (path.back() != '/') {
      full_path += '/';
    }
    full_path += entry_name;
    
    struct stat entry_stat;
    if (stat(full_path.c_str(), &entry_stat) == 0) {
      std::string list_item = entry_name + "\r\n";
      
      // Send data through TLS if secured data connection is used
      if (data_tls_context_ != nullptr) {
        esp_tls_conn_write(data_tls_context_, list_item.c_str(), list_item.length());
      } else {
        send(data_socket, list_item.c_str(), list_item.length(), 0);
      }
    }
  }

  closedir(dir);
  close(data_socket);
  close_data_connection(client_socket);
  send_response(client_socket, client_index, 226, "Directory send OK");
}

void FTPServer::start_file_upload(int client_socket, size_t client_index, const std::string& path) {
  int data_socket = open_data_connection(client_socket, client_index);
  if (data_socket < 0) {
    send_response(client_socket, client_index, 425, "Can't open data connection");
    return;
  }

  int file_fd = open(path.c_str(), O_WRONLY | O_CREAT | O_TRUNC, 0666);
  if (file_fd < 0) {
    close(data_socket);
    close_data_connection(client_socket);
    send_response(client_socket, client_index, 550, "Failed to open file for writing");
    return;
  }

  char buffer[2048];
  int len;
  
  if (data_tls_context_ != nullptr) {
    // Read from TLS data connection
    while ((len = esp_tls_conn_read(data_tls_context_, buffer, sizeof(buffer))) > 0) {
      write(file_fd, buffer, len);
    }
  } else {
    // Read from plain data socket
    while ((len = recv(data_socket, buffer, sizeof(buffer), 0)) > 0) {
      write(file_fd, buffer, len);
    }
  }

  close(file_fd);
  close(data_socket);
  close_data_connection(client_socket);
  send_response(client_socket, client_index, 226, "Transfer complete");
}

void FTPServer::start_file_download(int client_socket, size_t client_index, const std::string& path) {
  int data_socket = open_data_connection(client_socket, client_index);
  if (data_socket < 0) {
    send_response(client_socket, client_index, 425, "Can't open data connection");
    return;
  }

  int file_fd = open(path.c_str(), O_RDONLY);
  if (file_fd < 0) {
    close(data_socket);
    close_data_connection(client_socket);
    send_response(client_socket, client_index, 550, "Failed to open file for reading");
    return;
  }

  char buffer[2048];
  int len;
  
  while ((len = read(file_fd, buffer, sizeof(buffer))) > 0) {
    if (data_tls_context_ != nullptr) {
      // Write to TLS data connection
      esp_tls_conn_write(data_tls_context_, buffer, len);
    } else {
      // Write to plain data socket
      send(data_socket, buffer, len, 0);
    }
  }

  close(file_fd);
  close(data_socket);
  close_data_connection(client_socket);
  send_response(client_socket, client_index, 226, "Transfer complete");
}

bool FTPServer::is_running() const {
  return ftp_server_socket_ != -1;
}

}  // namespace ftp_server
}  // namespace esphome
