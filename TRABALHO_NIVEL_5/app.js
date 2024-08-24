const express = require('express')
const bodyParser = require('body-parser')
const crypto = require('crypto')
const { body, param, validationResult } = require('express-validator');
const { default: rateLimit } = require('express-rate-limit');

const app = express()
app.use(bodyParser.json())
const port = process.env.PORT || 3000

app.listen(port, () => {
  console.log(`Server is running on port ${port}`)
})

/*Endpoint para login do usuário*/
const loginLimiter = rateLimit({
    windowMs: 15 * 60 * 1000,
    max: 5,
    message: 'Muitas tentativas de login. Tente novamente mais tarde.'
});

app.post('/api/auth/login', loginLimiter, [
    body('username').isString().notEmpty(),
    body('password').isString().notEmpty()
], (req, res) => {
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
        return res.status(400).json({ errors: errors.array() });
    }

    const credentials = req.body;
    let userData = doLogin(credentials);
    if (userData) {
        const dataToEncrypt = JSON.stringify({ usuario_id: userData.id });
        const hashString = encrypt(Buffer.from(dataToEncrypt, "utf8"));
        res.json({ sessionid: hashString });
    } else {
        res.status(401).json({ message: 'Não Autorizado' });
    }
});


/* Endpoint para recuperação dos dados de todos os usuários cadastrados */
app.get('/api/users/:sessionid', [
    param('sessionid').isString().notEmpty()
], (req, res) => {
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
        return res.status(400).json({ errors: errors.array() });
    }

    const sessionid = req.params.sessionid;
    const perfil = getPerfil(sessionid);
    if (perfil !== 'admin') {
        return res.status(403).json({ message: 'Acesso proibido' });
    } else {
        res.status(200).json({ data: users });
    }
});

/* Endpoint para recuperação dos contratos existentes */
app.get('/api/contracts/:empresa/:inicio/:sessionid', [
    param('empresa').isString().notEmpty(),
    param('inicio').isString().isDate(),
    param('sessionid').isString().notEmpty()
], (req, res) => {
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
        return res.status(400).json({ errors: errors.array() });
    }

    const empresa = req.params.empresa;
    const dtInicio = req.params.inicio;
    const sessionid = req.params.sessionid;
    const result = getContracts(empresa, dtInicio);
    if (result.length > 0) {
        res.status(200).json({ data: result });
    } else {
        res.status(404).json({ data: 'Dados Não encontrados' });
    }
});

///////////////////////////////////////////////////////////////////////////////////////

const users = [
    {
        "username" : "user",
        "password" : "123456",
        "id" : 123,
        "email" : "user@dominio.com",
        "perfil": "user"
    },
    {
        "username" : "admin",
        "password" : "123456789",
        "id" : 124,
        "email" : "admin@dominio.com",
        "perfil": "admin"
    },
    {
        "username" : "colab",
        "password" : "123",
        "id" : 125,
        "email" : "colab@dominio.com",
        "perfil": "user"
    },

]

/* APP SERVICES */
function doLogin(credentials){
  let userData
  userData = users.find(item => {
    if(credentials?.username === item.username && credentials?.password === item.password)
      return item;
  });
  return userData;
}

/* CRIPTOGRAFAR */
const secretKey = "06955c9537e7adad0d9549b83acfe6fff697fd"; // chave criada 100% ALEATORIA
function encrypt(text) {
    const iv = crypto.randomBytes(16);
    const cipher = crypto.createCipheriv('aes-256-cbc', Buffer.from(secretKey, 'hex'), iv);
    let encrypted = cipher.update(text, 'utf8', 'hex');
    encrypted += cipher.final('hex');
    return iv.toString('hex') + ':' + encrypted;
}
function decrypt(encryptedText) {
    const textParts = encryptedText.split(':');
    const iv = Buffer.from(textParts.shift(), 'hex');
    const encryptedTextOnly = textParts.join(':');
    const decipher = crypto.createDecipheriv('aes-256-cbc', Buffer.from(secretKey, 'hex'), iv);
    let decrypted = decipher.update(encryptedTextOnly, 'hex', 'utf8');
    decrypted += decipher.final('utf8');
    return decrypted;
}

/* Recupera o perfil do usuário através da session-id */
function getPerfil(sessionId){
  const user = JSON.parse(decrypt(sessionId));
  const userData = users.find(item => parseInt(user.usuario_id) === parseInt(item.id));
  return userData.perfil;
}

/* Classe fake emulando um script externo, responsável pela execução de queries no banco de dados */
class Repository{
  execute(query){
    return [];
  }
}

/* Recupera, no banco de dados, os dados dos contratos */
function getContracts(empresa, inicio) {
    const repository = new Repository();
    const query = 'Select * from contracts Where empresa = ? And data_inicio = ?';
    return repository.execute(query, [empresa, inicio]);
}