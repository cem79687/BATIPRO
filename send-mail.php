<?php
/**
 * ════════════════════════════════════════════════════════
 *  BATI PRO & CO — send-mail.php
 *  Script d'envoi de formulaire de contact sécurisé
 *
 *  ► Pré-requis : PHP 7.4+ avec extension mail() activée
 *    (OVH, Ionos, o2switch… → activé par défaut)
 *
 *  ► Pour utiliser SMTP (Gmail, Brevo…) installez PHPMailer :
 *    composer require phpmailer/phpmailer
 *    puis décommentez la section SMTP en bas du fichier.
 * ════════════════════════════════════════════════════════
 */

/* ── 1. CONFIG — À PERSONNALISER ─────────────────────── */
define('DEST_EMAIL',    'contactbatipro.co@gmail.com'); // Email de réception
define('FROM_EMAIL',    'noreply@votredomaine.fr');      // Email expéditeur (domaine hébergé)
define('FROM_NAME',     'BATI PRO & CO — Formulaire');
define('SUBJECT_PREFIX','[Devis BPC]');
define('MAX_FILE_SIZE', 5 * 1024 * 1024); // 5 Mo par fichier
define('ALLOWED_TYPES', ['image/jpeg', 'image/png', 'image/webp']);
/* ─────────────────────────────────────────────────────── */


/* ── 2. SÉCURITÉ ──────────────────────────────────────── */
header('Content-Type: application/json; charset=utf-8');

// Autoriser uniquement les requêtes POST depuis votre propre domaine
if ($_SERVER['REQUEST_METHOD'] !== 'POST') {
    http_response_code(405);
    echo json_encode(['success' => false, 'message' => 'Méthode non autorisée.']);
    exit;
}

// Protection CSRF basique (referer check)
$referer = $_SERVER['HTTP_REFERER'] ?? '';
$host    = $_SERVER['HTTP_HOST']    ?? '';
if (!empty($host) && !empty($referer) && strpos($referer, $host) === false) {
    http_response_code(403);
    echo json_encode(['success' => false, 'message' => 'Accès refusé.']);
    exit;
}

// Honeypot anti-spam
if (!empty($_POST['website'])) {
    // Bot détecté — simuler un succès sans envoyer
    echo json_encode(['success' => true]);
    exit;
}

// Rate limiting basique par IP (1 envoi / 60s via fichier session)
session_start();
$now = time();
if (isset($_SESSION['last_submit']) && ($now - $_SESSION['last_submit']) < 60) {
    echo json_encode(['success' => false, 'message' => 'Merci de patienter avant de renvoyer le formulaire.']);
    exit;
}
$_SESSION['last_submit'] = $now;


/* ── 3. NETTOYAGE & VALIDATION ────────────────────────── */
function clean(string $val): string {
    return htmlspecialchars(strip_tags(trim($val)), ENT_QUOTES, 'UTF-8');
}

$errors = [];

$prenom       = clean($_POST['prenom']       ?? '');
$nom          = clean($_POST['nom']          ?? '');
$telephone    = clean($_POST['telephone']    ?? '');
$email        = filter_var(trim($_POST['email'] ?? ''), FILTER_SANITIZE_EMAIL);
$type_travaux = clean($_POST['type_travaux'] ?? '');
$localisation = clean($_POST['localisation'] ?? '');
$budget       = clean($_POST['budget']       ?? '');
$message      = clean($_POST['message']      ?? '');
$rgpd         = !empty($_POST['rgpd']);

if (empty($prenom))       $errors[] = 'Le prénom est requis.';
if (empty($nom))          $errors[] = 'Le nom est requis.';
if (empty($telephone))    $errors[] = 'Le téléphone est requis.';
if (!filter_var($email, FILTER_VALIDATE_EMAIL)) $errors[] = 'L\'adresse email est invalide.';
if (empty($type_travaux)) $errors[] = 'Le type de travaux est requis.';
if (empty($message))      $errors[] = 'Le message est requis.';
if (!$rgpd)               $errors[] = 'Vous devez accepter la politique de confidentialité.';

if (!empty($errors)) {
    echo json_encode(['success' => false, 'message' => implode(' ', $errors)]);
    exit;
}


/* ── 4. GESTION DES FICHIERS JOINTS ──────────────────── */
$attachments = [];

if (!empty($_FILES['photos']['name'][0])) {
    $files = $_FILES['photos'];
    $count = count($files['name']);

    for ($i = 0; $i < $count; $i++) {
        if ($files['error'][$i] !== UPLOAD_ERR_OK) continue;
        if ($files['size'][$i]  > MAX_FILE_SIZE)   continue;

        // Vérifier le type MIME réel (pas la déclaration client)
        $finfo    = new finfo(FILEINFO_MIME_TYPE);
        $mimeType = $finfo->file($files['tmp_name'][$i]);
        if (!in_array($mimeType, ALLOWED_TYPES)) continue;

        // Extension sûre
        $ext       = pathinfo($files['name'][$i], PATHINFO_EXTENSION);
        $safeName  = 'chantier_' . uniqid() . '.' . $ext;
        $tmpPath   = $files['tmp_name'][$i];

        $attachments[] = [
            'path'    => $tmpPath,
            'name'    => $safeName,
            'mime'    => $mimeType,
            'content' => file_get_contents($tmpPath),
        ];
    }
}


/* ── 5. CONSTRUCTION DE L'EMAIL ───────────────────────── */
$subject = SUBJECT_PREFIX . ' ' . $type_travaux . ' — ' . $prenom . ' ' . $nom;

$body  = "═══════════════════════════════════════\n";
$body .= "  NOUVELLE DEMANDE DE DEVIS — BATI PRO & CO\n";
$body .= "═══════════════════════════════════════\n\n";
$body .= "COORDONNÉES CLIENT\n";
$body .= "──────────────────\n";
$body .= "Prénom      : $prenom\n";
$body .= "Nom         : $nom\n";
$body .= "Téléphone   : $telephone\n";
$body .= "Email       : $email\n\n";
$body .= "DÉTAILS DU PROJET\n";
$body .= "──────────────────\n";
$body .= "Type de travaux : $type_travaux\n";
$body .= "Localisation    : " . ($localisation ?: 'Non renseignée') . "\n";
$body .= "Budget estimé   : " . ($budget ?: 'Non renseigné') . "\n\n";
$body .= "MESSAGE\n";
$body .= "──────────────────\n";
$body .= $message . "\n\n";

if (!empty($attachments)) {
    $body .= "PHOTOS JOINTES : " . count($attachments) . " fichier(s)\n";
}

$body .= "\n═══════════════════════════════════════\n";
$body .= "Envoyé le : " . date('d/m/Y à H:i') . "\n";
$body .= "IP client : " . ($_SERVER['REMOTE_ADDR'] ?? 'inconnue') . "\n";


/* ── 6A. ENVOI AVEC mail() natif PHP ──────────────────── */
$boundary = '----=_Part_' . md5(uniqid());

if (empty($attachments)) {
    /* Sans pièce jointe — email simple */
    $headers  = "From: " . FROM_NAME . " <" . FROM_EMAIL . ">\r\n";
    $headers .= "Reply-To: $prenom $nom <$email>\r\n";
    $headers .= "X-Mailer: PHP/" . PHP_VERSION . "\r\n";
    $headers .= "MIME-Version: 1.0\r\n";
    $headers .= "Content-Type: text/plain; charset=UTF-8\r\n";
    $headers .= "Content-Transfer-Encoding: 8bit\r\n";

    $sent = mail(DEST_EMAIL, '=?UTF-8?B?' . base64_encode($subject) . '?=', $body, $headers);

} else {
    /* Avec pièces jointes — email multipart */
    $headers  = "From: " . FROM_NAME . " <" . FROM_EMAIL . ">\r\n";
    $headers .= "Reply-To: $prenom $nom <$email>\r\n";
    $headers .= "X-Mailer: PHP/" . PHP_VERSION . "\r\n";
    $headers .= "MIME-Version: 1.0\r\n";
    $headers .= "Content-Type: multipart/mixed; boundary=\"$boundary\"\r\n";

    $emailBody  = "--$boundary\r\n";
    $emailBody .= "Content-Type: text/plain; charset=UTF-8\r\n";
    $emailBody .= "Content-Transfer-Encoding: 8bit\r\n\r\n";
    $emailBody .= $body . "\r\n";

    foreach ($attachments as $att) {
        $encoded    = base64_encode($att['content']);
        $emailBody .= "--$boundary\r\n";
        $emailBody .= "Content-Type: " . $att['mime'] . "; name=\"" . $att['name'] . "\"\r\n";
        $emailBody .= "Content-Transfer-Encoding: base64\r\n";
        $emailBody .= "Content-Disposition: attachment; filename=\"" . $att['name'] . "\"\r\n\r\n";
        $emailBody .= $encoded . "\r\n";
    }
    $emailBody .= "--$boundary--";

    $sent = mail(DEST_EMAIL, '=?UTF-8?B?' . base64_encode($subject) . '?=', $emailBody, $headers);
}


/* ── 7. EMAIL DE CONFIRMATION AU CLIENT ───────────────── */
if ($sent) {
    $confirmSubject = '=?UTF-8?B?' . base64_encode('Votre demande de devis — BATI PRO & CO') . '?=';
    $confirmBody    = "Bonjour $prenom,\n\n";
    $confirmBody   .= "Nous avons bien reçu votre demande de devis concernant :\n";
    $confirmBody   .= "→ $type_travaux\n\n";
    $confirmBody   .= "Miroslav vous recontactera sous 48h au numéro que vous avez indiqué.\n\n";
    $confirmBody   .= "En attendant, vous pouvez nous appeler directement :\n";
    $confirmBody   .= "📞 06 86 92 29 27\n\n";
    $confirmBody   .= "Cordialement,\n";
    $confirmBody   .= "L'équipe BATI PRO & CO\n";
    $confirmBody   .= "15 rue Noël Ruffier — 60 250 MOUY\n";

    $confirmHeaders  = "From: " . FROM_NAME . " <" . FROM_EMAIL . ">\r\n";
    $confirmHeaders .= "Reply-To: " . DEST_EMAIL . "\r\n";
    $confirmHeaders .= "MIME-Version: 1.0\r\n";
    $confirmHeaders .= "Content-Type: text/plain; charset=UTF-8\r\n";

    mail($email, $confirmSubject, $confirmBody, $confirmHeaders);
}


/* ── 8. RÉPONSE JSON ──────────────────────────────────── */
if ($sent) {
    echo json_encode(['success' => true]);
} else {
    http_response_code(500);
    echo json_encode([
        'success' => false,
        'message' => 'Le serveur n\'a pas pu envoyer l\'email. Veuillez appeler le 06 86 92 29 27.'
    ]);
}


/* ════════════════════════════════════════════════════════
   6B. ALTERNATIVE SMTP AVEC PHPMAILER (Gmail / Brevo…)
   ────────────────────────────────────────────────────────
   Si mail() ne fonctionne pas chez votre hébergeur :
   1. Décommentez le bloc ci-dessous
   2. Commentez la section 6A ci-dessus
   3. Installez PHPMailer : composer require phpmailer/phpmailer
   4. Renseignez vos identifiants SMTP

require 'vendor/autoload.php';
use PHPMailer\PHPMailer\PHPMailer;
use PHPMailer\PHPMailer\SMTP;

$mail = new PHPMailer(true);
try {
    $mail->isSMTP();
    $mail->Host       = 'smtp.gmail.com';       // ou smtp.ionos.fr, smtp-relay.brevo.com…
    $mail->SMTPAuth   = true;
    $mail->Username   = 'votre@gmail.com';
    $mail->Password   = 'votre_mot_de_passe_app'; // Mot de passe d'application Google
    $mail->SMTPSecure = PHPMailer::ENCRYPTION_STARTTLS;
    $mail->Port       = 587;
    $mail->CharSet    = 'UTF-8';

    $mail->setFrom(FROM_EMAIL, FROM_NAME);
    $mail->addAddress(DEST_EMAIL);
    $mail->addReplyTo($email, "$prenom $nom");
    $mail->Subject = $subject;
    $mail->Body    = $body;

    foreach ($attachments as $att) {
        $mail->addStringAttachment($att['content'], $att['name'], PHPMailer::ENCODING_BASE64, $att['mime']);
    }

    $mail->send();
    echo json_encode(['success' => true]);
} catch (Exception $e) {
    error_log('PHPMailer Error: ' . $mail->ErrorInfo);
    echo json_encode(['success' => false, 'message' => 'Erreur d\'envoi. Appelez le 06 86 92 29 27.']);
}
════════════════════════════════════════════════════════ */
?>
