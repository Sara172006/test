<?php
session_start();
$servername = "localhost";
$dbusername = "root";
$dbpassword = "";
$dbname = "user";
$conn = new mysqli($servername, $dbusername, $dbpassword, $dbname);
if ($conn->connect_error) {
    die("Connection failed: " . $conn->connect_error);
}
function e($str){
    return htmlspecialchars($str, ENT_QUOTES, 'UTF-8');
}
$errors = [
    'fname' => '',
    'lname' => '',
    'phone' => '',
    'password' => '',
    'general' => ''
];
$input = [
    'fname' => '',
    'lname' => '',
    'phone' => '',
];
if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    $input['fname'] = isset($_POST['fname']) ? trim($_POST['fname']) : '';
    $input['lname'] = isset($_POST['lname']) ? trim($_POST['lname']) : '';
    $input['phone'] = isset($_POST['phone']) ? trim($_POST['phone']) : '';
    $password_plain = isset($_POST['password']) ? $_POST['password'] : '';
    if ($input['fname'] === '' || !preg_match('/^[\p{Arabic}\s]+$/u', $input['fname'])) {
        $errors['fname'] = "نام را به فارسی بنویسید.";
    }
    if ($input['lname'] === '' || !preg_match('/^[\p{Arabic}\s]+$/u', $input['lname'])) {
        $errors['lname'] = "نام خانوادگی را به فارسی بنویسید.";
    }
    if (!preg_match('/^09\d{9}$/', $input['phone'])) {
        $errors['phone'] = "شماره تلفن باید با 09 شروع کند و دقیقاً 11 رقم عدد باشد.";
    }
    if (!preg_match('/^(?=.*[0-9])(?=.*[A-Za-z]).{6,}$/', $password_plain)) {
        $errors['password'] = "رمز عبور باید حداقل ۶ کاراکتر باشد و شامل حداقل یک حرف و یک عدد باشد.";
    }
    $hasAnyError = false;
    foreach ($errors as $v) { if ($v !== '') { $hasAnyError = true; break; } }
    if (!$hasAnyError) {
        $stmt = $conn->prepare("SELECT id FROM users WHERE phone = ?");
        $stmt->bind_param("s", $input['phone']);
        $stmt->execute();
        $stmt->store_result();
        if ($stmt->num_rows > 0) {
            $errors['phone'] = "این شماره قبلاً ثبت شده است.";
        }
        $stmt->close();
    }
    if (!$hasAnyError && $errors['phone'] === '') {
        $usedPassword = false;
        $res = $conn->query("SELECT password FROM users");
        if ($res) {
            while ($row = $res->fetch_assoc()) {
                if (password_verify($password_plain, $row['password'])) {
                    $usedPassword = true;
                    break;
                }
            }
            $res->free();
        }
        if ($usedPassword) {
            $errors['password'] = "این رمز عبور قبلاً توسط کاربر دیگری استفاده شده است. لطفاً رمز متفاوت انتخاب کنید.";
        }
    }
    $hasAnyError = false;
    foreach ($errors as $v) { if ($v !== '') { $hasAnyError = true; break; } }

    if (!$hasAnyError) {
        $hashed = password_hash($password_plain, PASSWORD_DEFAULT);

        $sql = "INSERT INTO users (fname, lname, phone, password, tagg) VALUES (?, ?, ?, ?, '')";
        $stmt = $conn->prepare($sql);
        if ($stmt === false) {
            $errors['general'] = "خطا در آماده‌سازی پرس‌وجو.";
        } else {
            $stmt->bind_param("ssss", $input['fname'], $input['lname'], $input['phone'], $hashed);
            if ($stmt->execute()) {
                session_regenerate_id(true);
                $_SESSION['user_id'] = $stmt->insert_id;
                $_SESSION['fname'] = $input['fname'];
                $_SESSION['lname'] = $input['lname'];
                header("Location: home.php");
                exit();
            } else {
                $errors['general'] = "خطا در ثبت‌نام: " . e($stmt->error);
            }
            $stmt->close();
        }
    }
}
?>

<!DOCTYPE html>
<html lang="fa">
<head>
    <meta charset="utf-8">
    <title>ثبت نام</title>
    <style>
        body { font-family: Tahoma, Arial, sans-serif; direction: rtl; padding: 20px; }
        .form-row { margin-bottom: 12px; }
        label { display:block; margin-bottom:6px; }
        input[type="text"], input[type="password"] { width: 300px; padding:8px; }
        .error { color: #b00020; margin-top:6px; }
        .success { color: green; }
    </style>
</head>
<body>
    <h2>فرم ثبت نام</h2>

    <?php if ($errors['general']): ?>
        <div class="error"><?php echo e($errors['general']); ?></div>
    <?php endif; ?>

    <form method="post" action="">
        <div class="form-row">
            <label>نام:</label>
            <input type="text" name="fname" value="<?php echo e($input['fname']); ?>">
            <?php if ($errors['fname']): ?><div class="error"><?php echo e($errors['fname']); ?></div><?php endif; ?>
        </div>

        <div class="form-row">
            <label>نام خانوادگی :</label>
            <input type="text" name="lname" value="<?php echo e($input['lname']); ?>">
            <?php if ($errors['lname']): ?><div class="error"><?php echo e($errors['lname']); ?></div><?php endif; ?>
        </div>

        <div class="form-row">
            <label>شماره تلفن :</label>
            <input type="text" name="phone" placeholder ="09" value="<?php echo e($input['phone']); ?>">
            <?php if ($errors['phone']): ?><div class="error"><?php echo e($errors['phone']); ?></div><?php endif; ?>
        </div>

        <div class="form-row">
            <label>رمز عبور:</label>
            <input type="password" name="password" value="">
            <?php if ($errors['password']): ?><div class="error"><?php echo e($errors['password']); ?></div><?php endif; ?>
        </div>

        <div class="form-row">
            <input type="submit" value="ثبت نام">
        </div>
    </form>
</body>
</html>