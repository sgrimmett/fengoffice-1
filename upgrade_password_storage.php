<?php
/**
 * One-time upgrade: move password storage to password_hash() (bcrypt).
 *
 *   php upgrade_password_storage.php
 *
 * 1. Widens contact_passwords.password so it can hold bcrypt hashes.
 * 2. Converts every password-history entry from the old reversible
 *    encryption (cp_encrypt) to a one-way bcrypt hash.
 * 3. Adds contacts.password_hash. From then on, new passwords are stored
 *    with bcrypt, and existing users are upgraded on their next login.
 *
 * Safe to run more than once. Back up the database first.
 */
if (php_sapi_name() !== 'cli') {
	header('HTTP/1.0 404 Not Found');
	die();
}

chdir(dirname(__FILE__));
define("CONSOLE_MODE", true);
include "init.php";
@set_time_limit(0);

function column_info($table, $column) {
	$rows = DB::executeAll("SHOW COLUMNS FROM `".TABLE_PREFIX.$table."` LIKE '".$column."'");
	return is_array($rows) && count($rows) > 0 ? $rows[0] : null;
}

// 1. widen the history column (bcrypt hashes are 60 chars, varchar(255) leaves room for argon2)
$col = column_info('contact_passwords', 'password');
if ($col && stripos($col['Type'], 'varchar(255)') === false) {
	DB::execute("ALTER TABLE `".TABLE_PREFIX."contact_passwords` MODIFY `password` varchar(255) NOT NULL");
	echo "Widened contact_passwords.password to varchar(255)\n";
}

// 2. convert the password history
$converted = 0;
$failed = 0;
$entries = ContactPasswords::instance()->findAll();
foreach ($entries as $entry) {
	if (ContactPasswords::isHashedHistoryEntry($entry->getPassword())) continue;
	$date = $entry->getPasswordDate();
	if (!$date instanceof DateTimeValue) { $failed++; continue; }
	$plain = cp_decrypt($entry->getPassword(), $date->getTimestamp());
	DB::execute("UPDATE `".TABLE_PREFIX."contact_passwords` SET `password` = ? WHERE `id` = ?",
		password_hash($plain, PASSWORD_DEFAULT), $entry->getId());
	$converted++;
}
echo "Password history: converted $converted entries" . ($failed ? ", skipped $failed without a date" : "") . "\n";

// 3. add contacts.password_hash, which switches the app over to bcrypt
if (!column_info('contacts', 'password_hash')) {
	DB::execute("ALTER TABLE `".TABLE_PREFIX."contacts` ADD COLUMN `password_hash` varchar(255) NULL DEFAULT NULL AFTER `token`");
	echo "Added contacts.password_hash\n";
}

$legacy = DB::executeOne("SELECT COUNT(*) AS c FROM `".TABLE_PREFIX."contacts` WHERE `user_type` > 0 AND (`password_hash` IS NULL OR `password_hash` = '') AND `token` <> ''");
echo "Done. ".array_var($legacy, 'c', 0)." users still have SHA-1 passwords; each is upgraded automatically at their next login.\n";
