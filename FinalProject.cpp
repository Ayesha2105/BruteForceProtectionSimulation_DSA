#include <iostream>
#include <string>
#include <ctime>
#include <fstream>
#include <cctype>
#include <algorithm>
#include <limits>
using namespace std;

// ==================== HELPER SECURITY FUNCTIONS ====================

string hashPassword(const string& password) {
    long long numericHash = 0;
    for (size_t i = 0; i < password.length(); i++) {
        int asciiValue = (int)password[i];
        numericHash += (asciiValue * (i + 1)) + (asciiValue * 10);
    }
    string hashStr = to_string(numericHash);
    int index = 0;
    while (hashStr.length() < 14) {
        char passwordChar = password[index % password.length()];
        int dynamicOffset = ((int)passwordChar + hashStr.length()) % 93 + 33;
        hashStr += (char)dynamicOffset;
        index++;
    }
    return hashStr.substr(0, 14);
}

string checkStrength(const string& pw) {
    bool upper = false, lower = false, digit = false, special = false;
    string specialChars = "!@#$%^&*_-+=";
    for (size_t i = 0; i < pw.length(); i++) {
        if (isupper(pw[i]))  upper   = true;
        if (islower(pw[i]))  lower   = true;
        if (isdigit(pw[i]))  digit   = true;
        if (specialChars.find(pw[i]) != string::npos) special = true;
    }
    if (pw.length() < 8 || !upper || !lower || !digit || !special)
        return "Weak";
    return "Strong";
}

string generatePassword(int length = 12) {
    string upper   = "ABCDEFGHIJKLMNOPQRSTUVWXYZ";
    string lower   = "abcdefghijklmnopqrstuvwxyz";
    string digits  = "0123456789";
    string special = "!@#$%^&*";
    string allChars = upper + lower + digits + special;

    string password = "";
    password += upper  [rand() % upper.length()];
    password += lower  [rand() % lower.length()];
    password += digits [rand() % digits.length()];
    password += special[rand() % special.length()];
    for (int i = 4; i < length; i++)
        password += allChars[rand() % allChars.length()];

    for (size_t i = password.length() - 1; i > 0; i--) {  //remove pattern by shuffling
        int j = rand() % (i + 1);
        swap(password[i], password[j]);
    }
    return password;
}

// Safe input: reads full line, trims whitespace, never crashes
string safeInput(const string& prompt) {
    string input;
    while (true) {
        cout << prompt;
        if (!getline(cin, input)) {
            cin.clear();
            cin.ignore(numeric_limits<streamsize>::max(), '\n');
            input = "";
        }
        // trim leading/trailing spaces
        size_t start = input.find_first_not_of(" \t\r\n");
        size_t end   = input.find_last_not_of(" \t\r\n");
        if (start == string::npos) { cout << "Input cannot be empty. Try again.\n"; continue; }
        return input.substr(start, end - start + 1);
    }
}

// ----------------- CORE OOP DATA ENTITIES -----------------

class UserProfile {
private:
    string username;
    string passwordHash;
public:
    UserProfile(string u, string h): username(u), passwordHash(h) {}
    string getUsername()     const { return username; }
    string getPasswordHash() const { return passwordHash; }
};

class IPTraffic {
private:
    string ipAddress;
    time_t blockTime;
public:
    IPTraffic(string ip, time_t releaseTime): ipAddress(ip), blockTime(releaseTime) {}
    string getIpAddress() const { return ipAddress; }
    time_t getBlockTime() const { return blockTime; }
};

// -----------------------IP ATTEMPT TRACKER ------------------------
// Tracks per-IP failed attempts across all usernames (linked list)node  creatted only when ip enter wrong pass


class IPAttemptNode {
    public:
        string ip;
        int failCount;
        IPAttemptNode* next;
        IPAttemptNode(string i) : ip(i), failCount(1), next(nullptr) {}
    };
class IPAttemptTracker {
private:
    IPAttemptNode* head;
public:
    IPAttemptTracker() : head(nullptr) {}

    int recordFailure(const string& ip) {
        for (IPAttemptNode* c = head; c; c = c->next)
            if (c->ip == ip) 
               return ++c->failCount;
        IPAttemptNode* n = new IPAttemptNode(ip);
        n->next = head; 
        head = n;
        return 1;
    }

    int getFailCount(const string& ip) {
        for (IPAttemptNode* c = head; c; c = c->next)
            if (c->ip == ip) 
                return c->failCount;
        return 0;
    }

    void resetIP(const string& ip) {
        for (IPAttemptNode* c = head; c; c = c->next)
            if (c->ip == ip) { 
                c->failCount = 0; 
            return; 
        }
    }
};

// ---------------------------------AuditLog: singly linked list,persisted to logs.txt
class LogNode {
    public:
        string  message;
        LogNode* next;
        LogNode(string msg) : message(msg), next(nullptr) {}
    };
class AuditLog {
private:
    LogNode* head;
public:
    AuditLog() : head(nullptr) {}

    void addEntry(const string& msg) { //insert at head  and write to file 
        LogNode* n = new LogNode(msg);
        n->next = head; 
        head = n;
        ofstream fout("logs.txt", ios::app);
        if (fout.is_open()) fout << msg << endl;
    }

    void printLog() {
        ifstream fin("logs.txt");
        if (!fin.is_open()) { cout << "(No logs found)\n"; return; }
        string line;
        while (getline(fin, line))
            cout << "Audit Event -> " << line << "\n";
    }
};

// -----------------------------UserDatabase: AVL tree-------------------------
class UserNode {
    public:
        UserProfile* data;
        int height;
        UserNode* left;
        UserNode* right;
        UserNode(UserProfile* d) : data(d), height(1), left(nullptr), right(nullptr) {}
};

class UserDatabase {
private:
    UserNode* root;

    int  getHeight (UserNode* n) { return n ? n->height : 0; }
    int  getBalance(UserNode* n) { return n ? getHeight(n->left) - getHeight(n->right) : 0; }

    UserNode* rotateRight(UserNode* y) {
        UserNode* x = y->left; 
        UserNode* T2 = x->right;
        x->right = y; 
        y->left = T2;
        y->height = max(getHeight(y->left), getHeight(y->right)) + 1;
        x->height = max(getHeight(x->left), getHeight(x->right)) + 1;
        return x;
    }
    UserNode* rotateLeft(UserNode* x) {
        UserNode* y = x->right; 
        UserNode* T2 = y->left;
        y->left = x; 
        x->right = T2;
        x->height = max(getHeight(x->left), getHeight(x->right)) + 1;
        y->height = max(getHeight(y->left), getHeight(y->right)) + 1;
        return y;
    }

    //---insert user in avl and file---
    UserNode* insert(UserNode* node, UserProfile* p, bool& success) {
        if (!node) { 
             success = true;
             return new UserNode(p);
            }
        if(p->getUsername() < node->data->getUsername()) 
            node->left  = insert(node->left,  p, success);
        else if (p->getUsername() > node->data->getUsername()) 
            node->right = insert(node->right, p, success);
        else   { 
            success = false; 
            return node; 
        }

        node->height = 1 + max(getHeight(node->left), getHeight(node->right));
        int bal = getBalance(node);
        if (bal >  1 && p->getUsername() < node->left->data->getUsername())  
            return rotateRight(node);
        if (bal < -1 && p->getUsername() > node->right->data->getUsername()) 
            return rotateLeft(node);
        if (bal >  1 && p->getUsername() > node->left->data->getUsername())  { 
            node->left  = rotateLeft(node->left);  
            return rotateRight(node);
         }
        if (bal < -1 && p->getUsername() < node->right->data->getUsername()) { 
            node->right = rotateRight(node->right); 
            return rotateLeft(node);
         }
        return node;
    }

    //--------------------searchinggg (Recursive Binary Search) --------------------------
    UserNode* search(UserNode* node, const string& u) {
        if (!node || node->data->getUsername() == u) return node;
        return (u < node->data->getUsername()) ? search(node->left, u) : search(node->right, u);
    }

    void displayAlphabetical(UserNode* node) {
        if (!node) return;
        displayAlphabetical(node->left);
        cout << "User: " << node->data->getUsername() << " | Hash: " << node->data->getPasswordHash() << "\n";
        displayAlphabetical(node->right);
    }

public:
    UserDatabase() : root(nullptr) {}
    //file handling in users.txt
    void saveUserToFile(const string& username, const string& hash) {
        ofstream fout("users.txt", ios::app);
        if (fout.is_open()) fout << username << " " << hash << "\n";
    }

    void loadUsersFromFile() {
        ifstream fin("users.txt");
        string username, hash;
        while (fin >> username >> hash) createAccount(username, hash);
    }

    bool createAccount(const string& u, const string& h) {
        bool status = false;
        root = insert(root, new UserProfile(u, h), status);
        return status;
    }

    UserProfile* getUser(const string& u) {
        UserNode* res = search(root, u);
        return res ? res->data : nullptr;
    }

    bool verifyUser(const string& u, const string& enteredHash) {
        UserProfile* user = getUser(u);
        return user && user->getPasswordHash() == enteredHash;
    }

    bool isDuplicate(const string& u) { return search(root, u) != nullptr; }
    void showDb() {
        if (!root) { cout << "(No users found)\n"; return; }
        displayAlphabetical(root);
    }
};

// -------------IPFirewall: AVL tree for only blocked IPs-------------

 class IPNode {
    public:
        IPTraffic* data;
        int height;
        IPNode* left;
        IPNode* right;
        IPNode(IPTraffic* d) : data(d), height(1), left(nullptr), right(nullptr) {}
    };

class IPFirewall {
private:
    IPNode* root;
    int  getHeight (IPNode* n) { return n ? n->height : 0; }
    int  getBalance(IPNode* n) { return n ? getHeight(n->left) - getHeight(n->right) : 0; }

    IPNode* rotateRight(IPNode* y) {
        IPNode* x = y->left; 
        IPNode* T2 = x->right;
        x->right = y; 
        y->left = T2;
        y->height = max(getHeight(y->left), getHeight(y->right)) + 1;
        x->height = max(getHeight(x->left), getHeight(x->right)) + 1;
        return x;
    }
    IPNode* rotateLeft(IPNode* x) {
        IPNode* y = x->right; 
        IPNode* T2 = y->left;
        y->left = x; 
        x->right = T2;
        x->height = max(getHeight(x->left), getHeight(x->right)) + 1;
        y->height = max(getHeight(y->left), getHeight(y->right)) + 1;
        return y;
    }

    IPNode* insert(IPNode* node, IPTraffic* t, bool& success) {
        if (!node) { 
            success = true; 
            return new IPNode(t); 
        }
        if (t->getIpAddress() < node->data->getIpAddress()) 
           node->left  = insert(node->left,  t, success);
        else if (t->getIpAddress() > node->data->getIpAddress()) 
           node->right = insert(node->right, t, success);
        else   { 
            success = false; 
            return node;
        }

        node->height = 1 + max(getHeight(node->left), getHeight(node->right));
        int bal = getBalance(node);
        if (bal >  1 && t->getIpAddress() < node->left->data->getIpAddress())  
            return rotateRight(node);
        if (bal < -1 && t->getIpAddress() > node->right->data->getIpAddress()) 
            return rotateLeft(node);
        if (bal >  1 && t->getIpAddress() > node->left->data->getIpAddress())  { 
            node->left  = rotateLeft(node->left);  
            return rotateRight(node); 
        }
        if (bal < -1 && t->getIpAddress() < node->right->data->getIpAddress()) { 
            node->right = rotateRight(node->right); 
            return rotateLeft(node); 
        }
        return node;
    }

    //------------- recursive binary ip search---------
    IPNode* search(IPNode* node, const string& ip) {
        if (!node || node->data->getIpAddress() == ip) return node;
        return (ip < node->data->getIpAddress()) ? search(node->left, ip) : search(node->right, ip);
    }

public:
    IPFirewall() : root(nullptr) {}
// save to blacklist .txt

    void saveBlockedIP(const string& ip, time_t banTime) {
        ofstream fout("blacklist.txt", ios::app);
        if (fout.is_open()) fout << ip << " " << banTime << "\n";
    }

    void loadBlockedIPs() {
        ifstream fin("blacklist.txt");
        string ip; time_t t;
        while (fin >> ip >> t) {
            bool s = false;
            root = insert(root, new IPTraffic(ip, t), s);
        }
    }

    bool isBlacklisted(const string& ip) {
        IPNode* node = search(root, ip);
        if (!node) return false;
        if (difftime(node->data->getBlockTime(), time(nullptr)) > 0) {
            cout << "Access Denied: IP (" << ip << ") is temporarily blocked.\n";
            return true;
        }
        return false;
    }

    //------------------*****function to block ip for 30 min********--------------------
    void blockIP(const string& ip, AuditLog& logger) {
        bool s = false;
        time_t ban = time(nullptr) + (30 * 60);
        root = insert(root, new IPTraffic(ip, ban), s);
        saveBlockedIP(ip, ban);
        logger.addEntry("WAF Action: Blocked malicious IP -> " + ip);
        cout << "[SECURITY] IP " << ip << " has been blocked for 30 minutes.\n";
    }
};

//------------------------ USERNAME BLOCK MANAGER (wrong attempts count ) (linked List)------------------------
// Blocks a username if it receives too many failed attempts from any IP

class UsernameBlockManager {
private:
    struct BlockNode {
        string username;
        int failCount;
        time_t blockUntil;
        BlockNode* next;
        BlockNode(string u) : username(u), failCount(1), blockUntil(0), next(nullptr) {}
    };
    BlockNode* head;
    static const int USERNAME_BLOCK_THRESHOLD = 3;
    static const int USERNAME_BLOCK_MINUTES   = 30;

public:
    UsernameBlockManager() : head(nullptr) {}

    bool recordFailure(const string& username, AuditLog& logger) {
        for (BlockNode* c = head; c; c = c->next) {
            if (c->username == username) {
                c->failCount++;
                logger.addEntry("Auth Failure: Attempt #" + to_string(c->failCount)  + " for username -> " + username);
                if (c->failCount >= USERNAME_BLOCK_THRESHOLD && c->blockUntil == 0) {
                    c->blockUntil = time(nullptr) + (USERNAME_BLOCK_MINUTES * 60); //******blocked for 30 min usename ***** */
                    logger.addEntry("Security: Username blocked -> " + username);
                    return true;
                }
                return false;
            }
        }
        BlockNode* n = new BlockNode(username);
        n->next = head;
        head = n;
        logger.addEntry("Auth Failure: First failed attempt for username -> " + username);
        return false;
    }

    bool isBlocked(const string& username) {
        for (BlockNode* c = head; c; c = c->next) {
            if (c->username == username) {
                if (c->blockUntil != 0 && difftime(c->blockUntil, time(nullptr)) > 0) {
                    cout << "Security Block: Username [" << username << "] is temporarily blocked (too many failed attempts).\n";
                    return true;
                }
                return false;
            }
        }
        return false;
    }

    void resetUsername(const string& username) {
        for (BlockNode* c = head; c; c = c->next)
            if (c->username == username) { c->failCount = 0; c->blockUntil = 0; return; }
    }
};

// ==================== *****MAIN******* ====================

int main() {
    srand(time(nullptr));
    UserDatabase  appDb;
    IPFirewall webWaf;
    AuditLog systemLog;
    IPAttemptTracker ipTracker;  //linked list object to track failed attempts of ip 
    UsernameBlockManager usernameBlocker; //linked list object to track failed attempts of username

    appDb.loadUsersFromFile();
    webWaf.loadBlockedIPs();

    int menuChoice = 0;

    do {
        cout << "\n========== SECURE LOGIN AND PROTECTION SYSTEM ==========\n";
        cout << "1. Register Account\n";
        cout << "2. Login\n";
        cout << "3. Check Password Strength\n";
        cout << "4. View Users\n";
        cout << "5. View Logs\n";
        cout << "6. Exit\n";
        cout << "Choice: ";

        string choiceStr;
        getline(cin, choiceStr);
        if (choiceStr.empty()) 
           continue;
        try { 
            menuChoice = stoi(choiceStr);
        }catch (...) { 
            cout << "Invalid choice. Enter a number 1-7.\n"; 
            continue; 
        }

        // ---- OPTION 1: REGISTER ----
        if (menuChoice == 1) {
            string userBuffer = safeInput("Enter Username: ");
            if (appDb.isDuplicate(userBuffer)) {
                cout << "Error: Username already exists.\n";
                continue;
            }
            string passBuffer;
            while (true) {
                passBuffer = safeInput("Enter Password: ");
                string result = checkStrength(passBuffer);
                cout << "Password Strength: " << result << "\n";

                if (result == "Weak") {
                    cout << "\n[!] Weak password. password Requirements:\n";
                    cout << "    - At least 8 characters\n";
                    cout << "    - Uppercase letter (A-Z)\n";
                    cout << "    - Lowercase letter (a-z)\n";
                    cout << "    - A digit (0-9)\n";
                    cout << "    - Special character (!@#$%^&*)\n";
                    systemLog.addEntry("Registration: Weak password rejected for -> " + userBuffer);

                    cout << "Want a suggested strong password? (y/n): ";
                    string genChoice;
                    getline(cin, genChoice);
                    if (!genChoice.empty() && (genChoice[0] == 'y' || genChoice[0] == 'Y')) {
                        string suggested = generatePassword(12);
                        cout << "Suggested : " << suggested << "\n";
                        cout << "Strength  : " << checkStrength(suggested) << "\n";
                        cout << "Use this password? (y/n): ";
                        string useIt; 
                        getline(cin, useIt);
                        if (!useIt.empty() && (useIt[0] == 'y' || useIt[0] == 'Y')) {
                            passBuffer = suggested;
                            break;
                        }
                    }
                    cout << "Please try again.\n";
                    continue;
                }
                break; // password is strong
            }

            string hash = hashPassword(passBuffer);
            appDb.createAccount(userBuffer, hash);
            appDb.saveUserToFile(userBuffer, hash);
            systemLog.addEntry("Registration: New account created -> " + userBuffer);
            cout << "Account created successfully!\n";
        }

        // ---- OPTION 2: LOGIN ----
        else if (menuChoice == 2) {
            string ipBuffer = safeInput("Enter your IP Address: ");
            if (webWaf.isBlacklisted(ipBuffer)) {
                systemLog.addEntry("Login Denied: Blocked IP attempted access -> " + ipBuffer);
                continue;
            }

            string userBuffer = safeInput("Enter Username: ");
            if (usernameBlocker.isBlocked(userBuffer)) {
                systemLog.addEntry("Login Denied: Blocked username -> " + userBuffer);
                continue;
            }

            UserProfile* user = appDb.getUser(userBuffer);
            if (!user) {
                cout << "Username not found.\n";
                int ipFails = ipTracker.recordFailure(ipBuffer);
                systemLog.addEntry("Login Failed: Unknown username [" + userBuffer + "] from IP " + ipBuffer);
                if (ipFails >= 3) {
                    webWaf.blockIP(ipBuffer, systemLog);
                    ipTracker.resetIP(ipBuffer);
                }
                continue;
            }

            string passBuffer = safeInput("Enter Password: ");
            string enteredHash = hashPassword(passBuffer);

            if (appDb.verifyUser(userBuffer, enteredHash)) {
                cout << "Login Successful! Welcome, " << userBuffer << ".\n";
                systemLog.addEntry("Login Success: " + userBuffer + " from IP " + ipBuffer);
                usernameBlocker.resetUsername(userBuffer);
                ipTracker.resetIP(ipBuffer);
            } else {
                cout << "Wrong password.\n";

                // IP-based tracking
                int ipFails = ipTracker.recordFailure(ipBuffer);
                systemLog.addEntry("Login Failed: Wrong password for [" + userBuffer + "] from IP " + ipBuffer);

                if (ipFails >= 3) {
                    webWaf.blockIP(ipBuffer, systemLog);
                    ipTracker.resetIP(ipBuffer);
                }

                // Username-based tracking
                bool usernameBlocked = usernameBlocker.recordFailure(userBuffer, systemLog);
                if (usernameBlocked) {
                    cout << "[SECURITY] Username " << userBuffer << " blocked for 30 minutes.\n";
                }
            }
        }

        // ---- OPTION 3: CHECK STRENGTH ----
        else if (menuChoice == 3) {
            string pw = safeInput("Enter password to check: ");
            cout << "Strength: " << checkStrength(pw) << "\n";
        }


        // ---- OPTION 4: VIEW USERS ----
        else if (menuChoice == 4) {
            string key = safeInput("Enter admin key: ");
            if (key == "admin123") appDb.showDb();
            else cout << "Access Denied: wrong key.\n";
        }

        // ---- OPTION 5: VIEW LOGS ----
        else if (menuChoice == 5) {
            string key = safeInput("Enter admin key: ");
            if (key == "admin123") systemLog.printLog();
            else cout << "Access Denied: wrong key.\n";
        }

        else if (menuChoice == 6) {
            cout << "Goodbye!\n";
        }
        else {
            cout << "Invalid choice. Enter 1-6.\n";
        }

    } while (menuChoice != 6);

    return 0;
}