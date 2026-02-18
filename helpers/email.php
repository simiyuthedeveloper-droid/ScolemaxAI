<?php
/**
 * Email Helper Functions
 * SMTP email sending with anti-spam headers and attachment support
 */

if (!function_exists('sendSMTPEmail')) {
    function sendSMTPEmail($config, $to_email, $to_name, $from_email, $from_name, $subject, $body_html, $attachment_path = null, $attachment_name = null) {
        $socket = null;
        
        try {
            $host = $config['smtp_host'];
            $port = $config['smtp_port'];
            $encryption = strtolower($config['smtp_encryption']);
            
            error_log("SMV Email Debug - Connecting to: $host:$port (encryption: $encryption)");
            
            if ($encryption === 'ssl') {
                $socket = @fsockopen('ssl://' . $host, $port, $errno, $errstr, 30);
            } else {
                $socket = @fsockopen($host, $port, $errno, $errstr, 30);
            }
            
            if (!$socket) {
                error_log("SMV Email Debug - Connection failed: $errstr ($errno)");
                return ['success' => false, 'message' => "Connection failed: $errstr ($errno)"];
            }
            
            stream_set_timeout($socket, 30);
            
            // Read initial greeting (can be multi-line)
            $response = '';
            while ($line = fgets($socket, 512)) {
                $response .= $line;
                if (preg_match('/^\d{3} /', $line)) {
                    break;
                }
            }
            error_log("SMV Email Debug - Initial response: " . trim($response));
            
            if (!preg_match('/^220/', $response)) {
                fclose($socket);
                error_log("SMV Email Debug - Server error: $response");
                return ['success' => false, 'message' => "Server error: $response"];
            }
            
            // EHLO - read complete multi-line response
            fputs($socket, "EHLO " . gethostname() . "\r\n");
            $response = '';
            while ($line = fgets($socket, 512)) {
                $response .= $line;
                if (preg_match('/^\d{3} /', $line)) {
                    break;
                }
            }
            error_log("SMV Email Debug - EHLO complete response: " . trim($response));
            
            // Check if AUTH LOGIN is supported
            if (!preg_match('/AUTH.*LOGIN/i', $response)) {
                fclose($socket);
                error_log("SMV Email Debug - AUTH LOGIN not supported");
                return ['success' => false, 'message' => 'Server does not support AUTH LOGIN'];
            }
            
            // AUTH LOGIN
            fputs($socket, "AUTH LOGIN\r\n");
            $response = fgets($socket, 512);
            error_log("SMV Email Debug - AUTH LOGIN response: " . trim($response));
            
            if (substr($response, 0, 3) != '334') {
                fclose($socket);
                error_log("SMV Email Debug - AUTH LOGIN failed: $response");
                return ['success' => false, 'message' => 'AUTH LOGIN not accepted: ' . trim($response)];
            }
            
            // Send username
            fputs($socket, base64_encode($config['smtp_username']) . "\r\n");
            $response = fgets($socket, 512);
            error_log("SMV Email Debug - Username response: " . trim($response));
            
            if (substr($response, 0, 3) != '334') {
                fclose($socket);
                error_log("SMV Email Debug - Username rejected: $response");
                return ['success' => false, 'message' => 'Username rejected: ' . trim($response)];
            }
            
            // Send password
            fputs($socket, base64_encode($config['smtp_password']) . "\r\n");
            $response = fgets($socket, 512);
            error_log("SMV Email Debug - Password response: " . trim($response));
            
            if (substr($response, 0, 3) != '235') {
                fclose($socket);
                error_log("SMV Email Debug - Authentication failed: $response");
                return ['success' => false, 'message' => 'Authentication failed: ' . trim($response)];
            }
            
            error_log("SMV Email Debug - Authentication successful!");
            
            // MAIL FROM
            fputs($socket, "MAIL FROM: <$from_email>\r\n");
            $response = fgets($socket, 512);
            error_log("SMV Email Debug - MAIL FROM response: " . trim($response));
            
            if (substr($response, 0, 3) != '250') {
                fclose($socket);
                error_log("SMV Email Debug - MAIL FROM failed: $response");
                return ['success' => false, 'message' => 'MAIL FROM failed: ' . trim($response)];
            }
            
            // RCPT TO
            fputs($socket, "RCPT TO: <$to_email>\r\n");
            $response = fgets($socket, 512);
            error_log("SMV Email Debug - RCPT TO response: " . trim($response));
            
            if (substr($response, 0, 3) != '250') {
                fclose($socket);
                error_log("SMV Email Debug - RCPT TO failed: $response");
                return ['success' => false, 'message' => 'RCPT TO failed: ' . trim($response)];
            }
            
            // DATA
            fputs($socket, "DATA\r\n");
            $response = fgets($socket, 512);
            error_log("SMV Email Debug - DATA response: " . trim($response));
            
            if (substr($response, 0, 3) != '354') {
                fclose($socket);
                error_log("SMV Email Debug - DATA command failed: $response");
                return ['success' => false, 'message' => 'DATA command failed: ' . trim($response)];
            }
            
            // Build message with ANTI-SPAM headers
            $boundary = '----=_Part_' . md5(uniqid(time()));
            
            // CRITICAL ANTI-SPAM HEADERS
            $message = "From: $from_name <$from_email>\r\n";
            $message .= "To: $to_name <$to_email>\r\n";
            $message .= "Reply-To: $from_email\r\n";
            $message .= "Return-Path: $from_email\r\n";
            $message .= "Subject: $subject\r\n";
            $message .= "Date: " . date('r') . "\r\n";
            $message .= "Message-ID: <" . md5(uniqid(time())) . "@" . parse_url($from_email, PHP_URL_HOST) . ">\r\n";
            $message .= "X-Mailer: SMV Security Platform v1.0\r\n";
            $message .= "X-Priority: 1 (Highest)\r\n";
            $message .= "X-MSMail-Priority: High\r\n";
            $message .= "Importance: High\r\n";
            $message .= "List-Unsubscribe: <mailto:unsubscribe@scolemax.co.ke>\r\n";
            $message .= "MIME-Version: 1.0\r\n";
            
            if ($attachment_path && file_exists($attachment_path)) {
                $message .= "Content-Type: multipart/mixed; boundary=\"$boundary\"\r\n";
            } else {
                $message .= "Content-Type: multipart/alternative; boundary=\"$boundary\"\r\n";
            }
            
            $message .= "\r\n";
            $message .= "This is a multi-part message in MIME format.\r\n\r\n";
            
            // HTML Body
            $message .= "--$boundary\r\n";
            $message .= "Content-Type: text/html; charset=UTF-8\r\n";
            $message .= "Content-Transfer-Encoding: 8bit\r\n\r\n";
            $message .= $body_html . "\r\n\r\n";
            
            // Attachment if provided
            if ($attachment_path && file_exists($attachment_path)) {
                $file_content = file_get_contents($attachment_path);
                $encoded_content = chunk_split(base64_encode($file_content));
                
                if (!$attachment_name) {
                    $attachment_name = basename($attachment_path);
                }
                
                $message .= "--$boundary\r\n";
                $message .= "Content-Type: application/zip; name=\"$attachment_name\"\r\n";
                $message .= "Content-Transfer-Encoding: base64\r\n";
                $message .= "Content-Disposition: attachment; filename=\"$attachment_name\"\r\n\r\n";
                $message .= $encoded_content . "\r\n";
                
                error_log("SMV Email Debug - Attachment added: $attachment_name (" . strlen($file_content) . " bytes)");
            }
            
            $message .= "--$boundary--\r\n";
            
            // Send message
            fputs($socket, $message . "\r\n.\r\n");
            $response = fgets($socket, 512);
            error_log("SMV Email Debug - Send response: " . trim($response));
            
            if (substr($response, 0, 3) != '250') {
                fclose($socket);
                error_log("SMV Email Debug - Send failed: $response");
                return ['success' => false, 'message' => 'Send failed: ' . trim($response)];
            }
            
            // QUIT
            fputs($socket, "QUIT\r\n");
            $response = fgets($socket, 512);
            error_log("SMV Email Debug - QUIT response: " . trim($response));
            fclose($socket);
            
            error_log("SMV Email Debug - Email sent successfully to: $to_email");
            return ['success' => true, 'message' => 'Email sent successfully'];
            
        } catch (Exception $e) {
            if ($socket) @fclose($socket);
            error_log("SMV Email Debug - Exception: " . $e->getMessage());
            return ['success' => false, 'message' => $e->getMessage()];
        }
    }
}
?>
