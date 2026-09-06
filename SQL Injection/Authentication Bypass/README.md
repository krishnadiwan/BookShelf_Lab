# BookShelf - SQL Injection Login Bypass

## Overview
While testing the login page of the BookShelf application, I found that the
username field is vulnerable to SQL Injection. This allows an attacker to
bypass authentication without knowing a valid username or password.

**Target:** `http://192.168.112.8:8080/BookShelf/index.jsp`
**Vulnerability:** Authentication Bypass via SQL Injection
**Field affected:** Username

---

## Steps to Reproduce

### 1. Testing the Username Field
I entered a basic SQL injection payload in the username field to see how
the app handled special characters:

```
' OR '1'='1
```

I left the password field as-is (any value works here since the query
gets bypassed).

![Login form with payload](images/01-login-payload.png)

### 2. Result — Login Bypassed
Clicking Login logged me straight in without valid credentials. The
welcome page even reflects the raw payload back as the "username", which
confirms the input isn't being sanitized or validated at all.

![Successful bypass](images/02-bypass-success.png)

### 3. Confirming It's a Real Injection (not a fluke)
To rule out coincidence, I tried a second, logically different payload:

```
' OR '1'!='2
```

This also evaluates to true, but uses a different comparison operator
than the first payload. Since it produced the exact same result (successful
login, bypassing auth), it confirms the backend is directly concatenating
user input into a SQL query rather than treating it as a parameter.

![Second payload in login form](images/03-second-payload.png)

![Second successful bypass](images/04-second-bypass.png)

---

## Root Cause
The login query is most likely built like this on the backend:

```sql
SELECT * FROM users WHERE username = '<input>' AND password = '<input>'
```

Since the input isn't sanitized, injecting `' OR '1'='1` turns the query
into something that's always true, returning a valid row and letting the
attacker log in without needing real credentials.

---

## Impact
- Full authentication bypass — no valid credentials needed
- Depending on how session/user data is handled after login, this could
  lead to accessing other students' records (e.g. via the "Enter your
  student ID" search field, which is worth testing next for SQLi too)

## Recommendation
- Use parameterized queries / prepared statements instead of string
  concatenation
- Apply input validation and escaping on all user-supplied fields
- Implement proper error handling so failed queries don't leak app logic

---

## Notes
This was tested in a local/lab environment (BookShelf on Kali) purely for
learning purposes.
