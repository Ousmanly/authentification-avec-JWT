import express from 'express';
import jwt from 'jsonwebtoken';
import bcrypt from 'bcrypt'

const app = express();
app.use(express.json());

const JWT_SECRET = 'Os1234';
const users = [
  {
    email: 'user@example.com',
    password: bcrypt.hashSync('password123', 10),
  }
];

const authenticateJWT = (req, res, next) => {
  const token = req.headers.authorization?.split(' ')[1];

  if (!token) {
    return res.status(401).json({ message: 'Accès non autorisé' });
  }

  jwt.verify(token, JWT_SECRET, (err, user) => {
    if (err) {
      return res.status(403).json({ message: 'Token invalide' });
    }

    req.user = user; 
    console.log(req.user)
    next();
  });
};

app.post('/api/login', (req, res) => {
  const { email, password } = req.body;
  const user = users.find(u => u.email === email);

  if (!user) {
    return res.status(401).json({ message: 'Utilisateur non trouvé' });
  }
  const isPasswordValid = bcrypt.compareSync(password, user.password);
  if (!isPasswordValid) {
    return res.status(401).json({ message: 'Mot de passe incorrect' });
  }
  const token = jwt.sign({ email: user.email }, JWT_SECRET, { expiresIn: '1h' });

  return res.json({ token });
});

app.get('/api/new-private-data', authenticateJWT, (req, res) => {
  res.json({ message: 'Voici des données privées', user: req.user });
});


const PORT = 3000;
app.listen(PORT, () => {
  console.log(`Serveur démarré sur le port ${PORT}`);
});