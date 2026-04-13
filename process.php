<?php
/**
 * process.php
 *
 * Responsavel por:
 * 1) Receber os dados do formulario via POST.
 * 2) Validar os dados basicos.
 * 3) Conectar no MySQL com PDO.
 * 4) Inserir no banco usando Prepared Statement (protege contra SQL Injection).
 */

declare(strict_types=1);

// Permite somente requisicoes POST para reduzir exposicao indevida da rota.
if ($_SERVER['REQUEST_METHOD'] !== 'POST') {
    header('Location: index.html');
    exit;
}

// Coleta e tratamento inicial dos dados recebidos.
$nome = trim($_POST['nome'] ?? '');
$email = trim($_POST['email'] ?? '');
$senha = $_POST['senha'] ?? '';

// Validacoes basicas de entrada.
if ($nome === '' || $email === '' || $senha === '') {
    exit('Erro: todos os campos sao obrigatorios.');
}

if (!filter_var($email, FILTER_VALIDATE_EMAIL)) {
    exit('Erro: e-mail invalido.');
}

if (mb_strlen($senha) < 8) {
    exit('Erro: a senha deve ter no minimo 8 caracteres.');
}

/**
 * Por seguranca, nunca armazenar senha em texto puro.
 * password_hash usa algoritmo forte (BCRYPT por padrao no PHP atual).
 */
$senhaHash = password_hash($senha, PASSWORD_DEFAULT);

// Configuracao de conexao (ajuste para o seu ambiente).
$host = 'localhost';
$dbname = 'cadastro_db';
$user = 'root';
$pass = '';
$charset = 'utf8mb4';

$dsn = "mysql:host={$host};dbname={$dbname};charset={$charset}";

$options = [
    PDO::ATTR_ERRMODE => PDO::ERRMODE_EXCEPTION,
    PDO::ATTR_DEFAULT_FETCH_MODE => PDO::FETCH_ASSOC,
    PDO::ATTR_EMULATE_PREPARES => false,
];

try {
    $pdo = new PDO($dsn, $user, $pass, $options);

    /**
     * Exemplo de tabela esperada:
     * CREATE TABLE usuarios (
     *   id INT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
     *   nome VARCHAR(100) NOT NULL,
     *   email VARCHAR(150) NOT NULL UNIQUE,
     *   senha_hash VARCHAR(255) NOT NULL,
     *   criado_em TIMESTAMP DEFAULT CURRENT_TIMESTAMP
     * );
     */
    $sql = 'INSERT INTO usuarios (nome, email, senha_hash) VALUES (:nome, :email, :senha_hash)';
    $stmt = $pdo->prepare($sql);

    // bindValue define explicitamente quais dados entram em cada parametro nomeado.
    $stmt->bindValue(':nome', $nome, PDO::PARAM_STR);
    $stmt->bindValue(':email', $email, PDO::PARAM_STR);
    $stmt->bindValue(':senha_hash', $senhaHash, PDO::PARAM_STR);

    $stmt->execute();

    echo 'Cadastro realizado com sucesso!';
} catch (PDOException $e) {
    // Em producao, prefira logar o erro em arquivo e mostrar mensagem generica ao usuario.
    if ((int) $e->getCode() === 23000) {
        exit('Erro: este e-mail ja esta cadastrado.');
    }

    error_log('Erro PDO em process.php: ' . $e->getMessage());
    exit('Erro interno ao processar o cadastro. Tente novamente mais tarde.');
}
