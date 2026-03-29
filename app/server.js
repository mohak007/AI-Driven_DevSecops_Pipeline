const express = require('express');
const app = express();
app.use(express.json());

app.get('/health', (req, res) => res.json({status: 'healthy'}));
app.post('/calc', (req, res) => {
  const {a, b} = req.body;
  res.json({result: a + b});
});

app.listen(3000, () => console.log('DevSecOps API on 3000'));
