const express = require('express');
const sqlite3 = require('sqlite3').verbose();
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');
const path = require('path');

const app = express();
const PORT = 5000;
const SECRET_KEY = "super_hemlig_nyckel_mvg"; 

app.use(express.json());

app.use(express.static(path.join(__dirname, 'public')));


const db = new sqlite3.Database('./database.sqlite', (err) => {
    if (err) {
        console.error("Kunde inte ansluta till databasen", err);
    } else {
        console.log("Ansluten till SQLite-databasen.");
    }
});


db.run(`CREATE TABLE IF NOT EXISTS users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    username TEXT UNIQUE,
    first_name TEXT,
    last_name TEXT,
    password TEXT
)`);


const authenticateToken = (req, res, next) => {
    const authHeader = req.headers['authorization'];
    const token = authHeader && authHeader.split(' ')[1]; 

    if (!token) {
        return res.status(401).json({ error: "Åtkomst nekad. Token saknas." });
    }

    jwt.verify(token, SECRET_KEY, (err, user) => {
        if (err) return res.status(403).json({ error: "Ogiltig eller utgången token." });
        req.user = user; // Spara användarinfon i requesten
        next(); 
    });
};


app.get('/users', authenticateToken, (req, res) => {
    db.all("SELECT id, username, first_name, last_name FROM users", [], (err, rows) => {
        if (err) return res.status(500).json({ error: err.message });
        res.json(rows);
    });
});


app.get('/users/:id', authenticateToken, (req, res) => {
    db.get("SELECT id, username, first_name, last_name FROM users WHERE id = ?", [req.params.id], (err, row) => {
        if (err) return res.status(500).json({ error: err.message });
        if (!row) return res.status(404).json({ error: "Användaren hittades inte." });
        res.json(row);
    });
});

app.post('/users', authenticateToken, async (req, res) => {
    const { username, first_name, last_name, password } = req.body;

    if (!username || !password) {
        return res.status(400).json({ error: "Username och password krävs." });
    }

    try {
        const hashedPassword = await bcrypt.hash(password, 10);

        db.run("INSERT INTO users (username, first_name, last_name, password) VALUES (?, ?, ?, ?)", 
        [username, first_name, last_name, hashedPassword], function(err) {
            if (err) return res.status(400).json({ error: "Kunde inte skapa. Username kanske redan finns?" });
            
            // Returnerar id som resursen fick i databasen
            res.status(201).json({ id: this.lastID, message: "Användare skapad!" });
        });
    } catch (error) {
        res.status(500).json({ error: "Serverfel." });
    }
});


app.put('/users/:id', authenticateToken, (req, res) => {
    const { first_name, last_name } = req.body;

    db.run("UPDATE users SET first_name = ?, last_name = ? WHERE id = ?", 
    [first_name, last_name, req.params.id], function(err) {
        if (err) return res.status(500).json({ error: err.message });
        if (this.changes === 0) return res.status(404).json({ error: "Användaren hittades inte." });

        db.get("SELECT id, username, first_name, last_name FROM users WHERE id = ?", [req.params.id], (err, row) => {
            res.status(200).json(row); // Returnerar uppdaterat objekt
        });
    });
});


app.post('/login', (req, res) => {
    const { username, password } = req.body;

    db.get("SELECT * FROM users WHERE username = ?", [username], async (err, user) => {
        if (err) return res.status(500).json({ error: err.message });
        if (!user) return res.status(401).json({ error: "Fel användarnamn eller lösenord." });

        const passwordMatch = await bcrypt.compare(password, user.password);
        if (!passwordMatch) return res.status(401).json({ error: "Fel användarnamn eller lösenord." });

        const token = jwt.sign({ id: user.id, username: user.username }, SECRET_KEY, { expiresIn: '1h' });
        res.status(200).json({ message: "Inloggning lyckades", token: token }); // Returnerar INTE användarinfo i klartext
    });
});


// Starta servern
app.listen(PORT, () => {
    console.log(`Servern är igång på http://localhost:${PORT}`);
});