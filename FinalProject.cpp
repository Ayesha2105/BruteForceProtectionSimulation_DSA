#include <iostream>
#include <string>
#include <ctime>
#include <cstdlib>
#include <iomanip>

using namespace std;


// Custom Hash Function 
long long hashPassword(const string& password) {
    long long hash = 5381;
    for (int i = 0; i < password.length(); i++) {
        hash = ((hash << 5) + hash) + (long long)password[i];
    }
    return hash < 0 ? -hash : hash;
}

// Password Strength Analyzer (Score out of 10)
int passwordStrength(const string& pw) {
    int score = 0;
    bool upper = false, lower = false, digit = false, special = false;

    for (int i = 0; i < pw.length(); i++) {
        if (isupper(pw[i])) upper = true;
        if (islower(pw[i])) lower = true;
        if (isdigit(pw[i])) digit = true;
        if (ispunct(pw[i])) special = true;
    }

    if (pw.length() >= 6)  score += 2;
    if (pw.length() >= 10) score += 2;
    if (pw.length() >= 14) score += 1;
    if (upper)   score += 1;
    if (lower)   score += 1;
    if (digit)   score += 1;
    if (special) score += 2;

    return min(score, 10);
}

void showStrengthBar(int score) {
    cout << "Strength [";
    for (int i = 0; i < 10; i++) cout << (i < score ? "#" : "-");
    cout << "] " << score << "/10 -> ";
    if (score <= 3) cout << "Weak\n";
    else if (score <= 6) cout << "Moderate\n";
    else if (score <= 8) cout << "Strong\n";
    else cout << "Very Strong\n";
}

string generatePassword() {
    const string chars = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789!@#$%^&*()";
    string result = "";
    for (int i = 0; i < 14; i++) {
        result += chars[rand() % chars.size()];
    }
    return result;
}

// 2. LINEAR DATA STRUCTURE: SINGLY LINKED LIST 
// =========================================================================
struct LogNode {
    string message;
    string timestamp;
    LogNode* next;
    LogNode(string msg, string ts) : message(msg), timestamp(ts), next(nullptr) {}
};

class AuditLog {
private:
    LogNode* head;
    string getSystemTime() {
        time_t t = time(nullptr);
        char buf[25];
        strftime(buf, sizeof(buf), "%Y-%m-%d %H:%M:%S", localtime(&t));
        return string(buf);
    }

public:
    AuditLog() : head(nullptr) {}

    void addEntry(string msg) {
        LogNode* newNode = new LogNode(msg, getSystemTime());
        newNode->next = head; // New logs pushed to top
        head = newNode;
    }

    void printLog() {
        if (!head) { cout << "(No logs registered)\n"; return; }
        LogNode* temp = head;
        while (temp) {
            cout << "[" << temp->timestamp << "] " << temp->message << "\n";
            temp = temp->next;
        }
    }
};

// 3. NON-LINEAR DATA STRUCTURE: USER AVL DATABASE 
// =========================================================================
struct UserNode {
    string username;
    long long passwordHash;
    int height;
    UserNode *left, *right;
    UserNode(string u, long long h) : username(u), passwordHash(h), height(1), left(nullptr), right(nullptr) {}
};

class UserDatabase {
private:
    UserNode* root;

    int getHeight(UserNode* n) { return n ? n->height : 0; }
    int getBalance(UserNode* n) { return n ? getHeight(n->left) - getHeight(n->right) : 0; }

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

    UserNode* insert(UserNode* node, string u, long long h, bool& checkingFlag) {
        if (!node) { checkingFlag = true; return new UserNode(u, h); }
        if (u < node->username) node->left = insert(node->left, u, h, checkingFlag);
        else if (u > node->username) node->right = insert(node->right, u, h, checkingFlag);
        else { checkingFlag = false; return node; }

        node->height = 1 + max(getHeight(node->left), getHeight(node->right));
        int balance = getBalance(node);

        if (balance > 1 && u < node->left->username) return rotateRight(node);
        if (balance < -1 && u > node->right->username) return rotateLeft(node);
        if (balance > 1 && u > node->left->username) {
            node->left = rotateLeft(node->left);
            return rotateRight(node);
        }
        if (balance < -1 && u < node->right->username) {
            node->right = rotateRight(node->right);
            return rotateLeft(node);
        }
        return node;
    }

    UserNode* search(UserNode* node, string u) {
        if (!node || node->username == u) return node;
        return (u < node->username) ? search(node->left, u) : search(node->right, u);
    }

    void displayAlphabetical(UserNode* node) {
        if (node) {
            displayAlphabetical(node->left);
            cout << left << setw(20) << node->username << "Hash: " << node->passwordHash << "\n";
            displayAlphabetical(node->right);
        }
    }

public:
    UserDatabase() : root(nullptr) {}

    bool createAccount(string u, long long h) {
        bool status = false;
        root = insert(root, u, h, status);
        return status;
    }

    bool verifyUser(string u, long long h) {
        UserNode* res = search(root, u);
        return res && res->passwordHash == h;
    }

    bool isDuplicate(string u) { return search(root, u) != nullptr; }
    
    void showDb() {
        if (!root) { cout << "(No credentials stored)\n"; return; }
        cout << left << setw(20) << "USERNAME" << "PASSWORD HASH VALUE\n";
        cout << string(50, '-') << "\n";
        displayAlphabetical(root);
    }
};

// =========================================================================
// 4. FIREWALL UTILITY: STRUCT-BASED IP TRACKING
struct IPData {
    string ipAddress;
    int failedAttempts;
    time_t blockTime;
};

class Firewall {
private:
    IPData list[100]; 
    int count;

public:
    Firewall() : count(0) {}

    int findIP(string ip) {
        for (int i = 0; i < count; i++) {
            if (list[i].ipAddress == ip) return i;
        }
        return -1;
    }

    bool checkStatusAndFilter(string ip, AuditLog& logger) {
        int idx = findIP(ip);
        if (idx == -1) return false;

        time_t now = time(nullptr);
        if (list[idx].failedAttempts >= 4) {
            if (difftime(list[idx].blockTime, now) > 0) {
                cout << "FIREWALL ACTIVE: This IP is blocked for " << (int)difftime(list[idx].blockTime, now) << " more seconds.\n";
                return true;
            } else {
                list[idx].failedAttempts = 0;
                list[idx].blockTime = 0;
            }
        }
        return false;
    }

    void recordViolation(string ip, AuditLog& logger) {
        int idx = findIP(ip);
        if (idx == -1) {
            list[count] = {ip, 1, 0};
            idx = count++;
        } else {
            list[idx].failedAttempts++;
        }

        if (list[idx].failedAttempts >= 4) {
            list[idx].blockTime = time(nullptr) + (30 * 60); // 30-minute block
            logger.addEntry("FIREWALL: Blocked hostile IP: " + ip);
            cout << "ALERT: 4 Failed Attempts reached. IP address has been restricted for 30 minutes.\n";
        } else {
            cout << "Invalid Credentials. Attempts remaining for this IP: " << (4 - list[idx].failedAttempts) << "\n";
        }
    }

    void wipeRecord(string ip) {
        int idx = findIP(ip);
        if (idx != -1) {
            list[idx].failedAttempts = 0;
            list[idx].blockTime = 0;
        }
    }
};



// ===================================main======================================
int main() {
    srand(time(nullptr));
    UserDatabase appDb;
    Firewall webWaf;
    AuditLog systemLog;

    int inputChoice;
    string u, p, networkIp;

    do {
        cout << "\n===============================\n";
        cout << "   CYBERGUARD AUTH INTERFACE\n";
        cout << "===============================\n";
        cout << "1. Create New Account\n2. Secure Login\n3. Generate Strong Pass\n4. Diagnostic Strength Check\n5. Admin: Read DB Hashes\n6. Admin: Read System Logs\n7. Quit System\nChoice: ";
        cin >> inputChoice;

        if (inputChoice == 1) {
            cout << "Enter target Username: "; cin >> u;
            if (appDb.isDuplicate(u)) { cout << "Registration Failed: Handle already in use.\n"; continue; }
            cout << "Assign System Password: "; cin >> p;
            showStrengthBar(passwordStrength(p));
            if (passwordStrength(p) < 4) { cout << "Account Denied: Password strategy does not pass threshold.\n"; continue; }
            
            appDb.createAccount(u, hashPassword(p));
            systemLog.addEntry("USER MANAGER: Provisioned profile for " + u);
            cout << "Account configured successfully.\n";

        } else if (inputChoice == 2) {
            cout << "Enter Device Target IP: "; cin >> networkIp;
            if (webWaf.checkStatusAndFilter(networkIp, systemLog)) continue;

            char retryChoice = 'y';
            while (retryChoice == 'y' || retryChoice == 'Y') {
                cout << "\n--- Secure Login Gateway ---\n";
                cout << "Username: "; cin >> u;
                cout << "Password: "; cin >> p;

                if (appDb.verifyUser(u, hashPassword(p))) {
                    cout << "\n[SUCCESS] Access Authorized.\n";
                    webWaf.wipeRecord(networkIp);
                    systemLog.addEntry("AUTH GATEWAY: Successful login for " + u);
                    break;
                } else {
                    systemLog.addEntry("AUTH GATEWAY: Failed login attempt for username " + u);
                    webWaf.recordViolation(networkIp, systemLog);
                    
                    if (webWaf.checkStatusAndFilter(networkIp, systemLog)) break;

                    cout << "\nWould you like to try again? (y/n): "; cin >> retryChoice;
                }
            }

        } else if (inputChoice == 3) {
            p = generatePassword();
            cout << "\nGenerated secure password: " << p << "\n";
            showStrengthBar(passwordStrength(p));
            systemLog.addEntry("SYS UTILS: Random password generated.");

        } else if (inputChoice == 4) {
            cout << "Provide input password string: "; cin >> p;
            showStrengthBar(passwordStrength(p));

        } else if (inputChoice == 5) {
            cout << "Admin Key: "; cin >> p;
            if (p == "admin123") {
                appDb.showDb();
                systemLog.addEntry("SYS AUDIT: DB Hash Tables dumped by root.");
            } else {
                cout << "Access Blocked.\n";
                systemLog.addEntry("ALARM: Unauthorized admin verification failure.");
            }

        } else if (inputChoice == 6) {
            cout << "Admin Key: "; cin >> p;
            if (p == "admin123") systemLog.printLog();
            else {
                cout << "Access Blocked.\n";
                systemLog.addEntry("ALARM: Unauthorized attempt to view logger logs.");
            }
        }
    } while (inputChoice != 7);

    return 0;
}