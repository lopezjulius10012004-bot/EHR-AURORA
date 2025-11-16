<?php
// Start session and check authentication first
if (session_status() === PHP_SESSION_NONE) {
    session_start();
}

if (!isset($_SESSION['admin'])) {
    header("Location: index.php");
    exit();
}

// Include required files AFTER session check
include "db.php";
include "audit_trail.php";

$page_title = "Patients Management";
$msg = "";
$error = "";

// CSRF token for security
if (!isset($_SESSION['csrf_token'])) {
    $_SESSION['csrf_token'] = bin2hex(random_bytes(32));
}

// Enhanced input sanitization function
function sanitize_input($conn, $data) {
    return trim($data);
}

// Validate date format
function validate_date($date) {
    if (empty($date)) return true; // Allow empty dates
    if (!preg_match('/^\d{4}-\d{2}-\d{2}$/', $date)) return false;
    if (strtotime($date) > time()) return false; // No future dates
    return true;
}



// Add patient with enhanced validation
if (isset($_POST['add_patient'])) {
    // CSRF protection
    if (!isset($_POST['csrf_token']) || $_POST['csrf_token'] !== $_SESSION['csrf_token']) {
        $error = "Security error: Invalid request.";
    } else {
        $fullname = sanitize_input($conn, $_POST['fullname'] ?? "");
        $dob = sanitize_input($conn, $_POST['dob'] ?? "");
        $age = intval($_POST['age'] ?? 0);
        $gender = sanitize_input($conn, $_POST['gender'] ?? "");
        $religion = sanitize_input($conn, $_POST['religion'] ?? "");
        $marital_status = sanitize_input($conn, $_POST['marital_status'] ?? "");
        $occupation = sanitize_input($conn, $_POST['occupation'] ?? "");
        $primary_contact = sanitize_input($conn, $_POST['primary_contact'] ?? "");
        $secondary_contact = sanitize_input($conn, $_POST['secondary_contact'] ?? "");
        $email_address = sanitize_input($conn, $_POST['email_address'] ?? "");
        $street_address = sanitize_input($conn, $_POST['street_address'] ?? "");
        $city = sanitize_input($conn, $_POST['city'] ?? "");
        $state = sanitize_input($conn, $_POST['state'] ?? "");
        $zip_code = sanitize_input($conn, $_POST['zip_code'] ?? "");
        $contact_name = sanitize_input($conn, $_POST['contact_name'] ?? "");
        $contact_phone = sanitize_input($conn, $_POST['contact_phone'] ?? "");
        $relationship = sanitize_input($conn, $_POST['relationship'] ?? "");
        $insurance_provider = sanitize_input($conn, $_POST['insurance_provider'] ?? "");
        $policy_number = sanitize_input($conn, $_POST['policy_number'] ?? "");
        $group_number = sanitize_input($conn, $_POST['group_number'] ?? "");

        // Enhanced validation
        if (empty($fullname)) {
            $error = "Patient name is required.";
        } elseif (strlen($fullname) < 2) {
            $error = "Patient name must be at least 2 characters.";
        } elseif (!validate_date($dob)) {
            $error = "Invalid date format for DOB. Use YYYY-MM-DD and no future dates.";
        } else {
            // Check for duplicates
            $check_stmt = $conn->prepare("SELECT id FROM patients WHERE fullname = ? AND dob = ? LIMIT 1");
            $check_stmt->bind_param("ss", $fullname, $dob);
            $check_stmt->execute();

            if ($check_stmt->get_result()->num_rows > 0) {
                $error = "A patient with this name and DOB already exists.";
                $check_stmt->close();
            } else {
                $check_stmt->close();

                $stmt = $conn->prepare("INSERT INTO patients (fullname, dob, age, gender, religion, marital_status, occupation, primary_contact, secondary_contact, email_address, street_address, city, state, zip_code, contact_name, contact_phone, relationship, insurance_provider, policy_number, group_number) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)");
                if ($stmt && $stmt->bind_param("ssisssssssssssssssss", $fullname, $dob, $age, $gender, $religion, $marital_status, $occupation, $primary_contact, $secondary_contact, $email_address, $street_address, $city, $state, $zip_code, $contact_name, $contact_phone, $relationship, $insurance_provider, $policy_number, $group_number) && $stmt->execute()) {
                    $patient_id = $conn->insert_id;

                    // Log audit trail
                $new_values = [
                    'fullname' => $fullname,
                    'dob' => $dob,
                    'age' => $age,
                    'gender' => $gender,
                    'religion' => $religion,
                    'marital_status' => $marital_status,
                    'occupation' => $occupation,
                    'primary_contact' => $primary_contact,
                    'secondary_contact' => $secondary_contact,
                    'email_address' => $email_address,
                    'street_address' => $street_address,
                    'city' => $city,
                    'state' => $state,
                    'zip_code' => $zip_code,
                    'contact_name' => $contact_name,
                    'contact_phone' => $contact_phone,
                    'relationship' => $relationship,
                    'insurance_provider' => $insurance_provider,
                    'policy_number' => $policy_number,
                    'group_number' => $group_number
                ];
                    log_audit($conn, 'INSERT', 'patients', $patient_id, $patient_id, null, $new_values);
                    $msg = "Patient added successfully.";
                    $stmt->close();
                } else {
                    $error = "Error adding patient. Please try again.";
                }
            }
        }

        // Regenerate CSRF token
        $_SESSION['csrf_token'] = bin2hex(random_bytes(32));
    }
}

// Update patient with enhanced validation
if (isset($_POST['update_patient'])) {
    // CSRF protection
    if (!isset($_POST['csrf_token']) || $_POST['csrf_token'] !== $_SESSION['csrf_token']) {
        $error = "Security error: Invalid request.";
    } else {
        $id = intval($_POST['id']);
        $fullname = sanitize_input($conn, $_POST['fullname'] ?? "");
        $dob = sanitize_input($conn, $_POST['dob'] ?? "");
        $age = intval($_POST['age'] ?? 0);
        $gender = sanitize_input($conn, $_POST['gender'] ?? "");
        $religion = sanitize_input($conn, $_POST['religion'] ?? "");
        $marital_status = sanitize_input($conn, $_POST['marital_status'] ?? "");
        $occupation = sanitize_input($conn, $_POST['occupation'] ?? "");
        $primary_contact = sanitize_input($conn, $_POST['primary_contact'] ?? "");
        $secondary_contact = sanitize_input($conn, $_POST['secondary_contact'] ?? "");
        $email_address = sanitize_input($conn, $_POST['email_address'] ?? "");
        $street_address = sanitize_input($conn, $_POST['street_address'] ?? "");
        $city = sanitize_input($conn, $_POST['city'] ?? "");
        $state = sanitize_input($conn, $_POST['state'] ?? "");
        $zip_code = sanitize_input($conn, $_POST['zip_code'] ?? "");
        $contact_name = sanitize_input($conn, $_POST['contact_name'] ?? "");
        $contact_phone = sanitize_input($conn, $_POST['contact_phone'] ?? "");
        $relationship = sanitize_input($conn, $_POST['relationship'] ?? "");
        $insurance_provider = sanitize_input($conn, $_POST['insurance_provider'] ?? "");
        $policy_number = sanitize_input($conn, $_POST['policy_number'] ?? "");
        $group_number = sanitize_input($conn, $_POST['group_number'] ?? "");

        // Enhanced validation
        if (empty($fullname)) {
            $error = "Patient name is required.";
        } elseif (strlen($fullname) < 2) {
            $error = "Patient name must be at least 2 characters.";
        } elseif (!validate_date($dob)) {
            $error = "Invalid date format for DOB. Use YYYY-MM-DD and no future dates.";
        } else {
            // Get old values for audit trail
            $old_values = get_record_values($conn, 'patients', $id);

            $stmt = $conn->prepare("UPDATE patients SET fullname=?, dob=?, age=?, gender=?, religion=?, marital_status=?, occupation=?, primary_contact=?, secondary_contact=?, email_address=?, street_address=?, city=?, state=?, zip_code=?, contact_name=?, contact_phone=?, relationship=?, insurance_provider=?, policy_number=?, group_number=? WHERE id=?");
            if ($stmt && $stmt->bind_param("ssissssssssssssssssssi", $fullname, $dob, $age, $gender, $religion, $marital_status, $occupation, $primary_contact, $secondary_contact, $email_address, $street_address, $city, $state, $zip_code, $contact_name, $contact_phone, $relationship, $insurance_provider, $policy_number, $group_number, $id) && $stmt->execute()) {
                // Log audit trail
                $new_values = [
                    'fullname' => $fullname,
                    'dob' => $dob,
                    'age' => $age,
                    'gender' => $gender,
                    'marital_status' => $marital_status,
                    'occupation' => $occupation,
                    'primary_contact' => $primary_contact,
                    'secondary_contact' => $secondary_contact,
                    'email_address' => $email_address,
                    'street_address' => $street_address,
                    'city' => $city,
                    'state' => $state,
                    'zip_code' => $zip_code,
                    'contact_name' => $contact_name,
                    'contact_phone' => $contact_phone,
                    'relationship' => $relationship,
                    'insurance_provider' => $insurance_provider,
                    'policy_number' => $policy_number,
                    'group_number' => $group_number
                ];
                log_audit($conn, 'UPDATE', 'patients', $id, $id, $old_values, $new_values);
                $msg = "Patient updated successfully.";
                $stmt->close();
            } else {
                $error = "Error updating patient. Please try again.";
            }
        }

        // Regenerate CSRF token
        $_SESSION['csrf_token'] = bin2hex(random_bytes(32));
    }
}

// Delete patient (cascades) with CSRF protection
if (isset($_GET['delete']) && isset($_GET['csrf_token']) && $_GET['csrf_token'] === $_SESSION['csrf_token']) {
    $id = intval($_GET['delete']);
    
    // Get old values for audit trail before deletion
    $old_values = get_record_values($conn, 'patients', $id);
    
    $stmt = $conn->prepare("DELETE FROM patients WHERE id=?");
    if ($stmt && $stmt->bind_param("i", $id) && $stmt->execute()) {
        // Log audit trail
        log_audit($conn, 'DELETE', 'patients', $id, $id, $old_values, null);
        $msg = "Patient deleted (and related records).";
        $stmt->close();
    } else {
        $error = "Error deleting patient.";
    }
    
    // Regenerate CSRF token
    $_SESSION['csrf_token'] = bin2hex(random_bytes(32));
}

// For edit form
$edit_patient = null;
if (isset($_GET['edit'])) {
    $id = intval($_GET['edit']);
    $stmt = $conn->prepare("SELECT * FROM patients WHERE id=?");
    if ($stmt && $stmt->bind_param("i", $id) && $stmt->execute()) {
        $res = $stmt->get_result();
        $edit_patient = $res->fetch_assoc();
        $stmt->close();
    }
}

include "header.php";
?>

<style>
    body {
      background-color: #ffffff;
      font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
      padding-top: 5rem;
    }

    .btn-primary {
        background-color: var(--primary-color);
        border-color: var(--primary-color);
    }
    .btn-primary:hover {
        background-color: var(--accent-color);
        border-color: var(--accent-color);
    }
    
    .alert {
        border-radius: 0.5rem;
        border: none;
    }
    
    .card {
        border-radius: 0.75rem;
    }
    
    .table-responsive {
        border-radius: 0.5rem;
        overflow-x: auto;
        -webkit-overflow-scrolling: touch;
    }
</style>

<div class="container mt-4">
    <div class="card mb-4">
        <div class="card-header d-flex justify-content-between align-items-center">
            <h5 class="mb-0"><i class="bi bi-people-fill me-2"></i>Manage Patients</h5>   
        </div>
        <div class="card-body">
            <!-- Success/Error Messages -->
            <?php if ($msg): ?>
                <div class="alert alert-success alert-dismissible fade show" role="alert">
                    <i class="bi bi-check-circle-fill me-2"></i><?php echo htmlspecialchars($msg); ?>
                    <button type="button" class="btn-close" data-bs-dismiss="alert" aria-label="Close"></button>
                </div>
            <?php endif; ?>
            <?php if ($error): ?>
                <div class="alert alert-danger alert-dismissible fade show" role="alert">
                    <i class="bi bi-exclamation-triangle-fill me-2"></i><?php echo htmlspecialchars($error); ?>
                    <button type="button" class="btn-close" data-bs-dismiss="alert" aria-label="Close"></button>
                </div>
            <?php endif; ?>

            <!-- Add/Edit Patient Form -->
            <div class="card mb-3 p-3">
                <h6><?php echo $edit_patient ? "Edit Patient" : "Add Patient"; ?></h6>
                <form method="post" class="row g-3" enctype="multipart/form-data"  novalidate>
                    <input type="hidden" name="csrf_token" value="<?php echo $_SESSION['csrf_token']; ?>">
                    <input type="hidden" name="id" value="<?php echo $edit_patient ? $edit_patient['id'] : ''; ?>">

                    <!-- Personal Information -->
                    <h6 class="mt-3">Personal Information</h6>
                    <div class="col-md-6">
                        <label for="fullname" class="form-label">Full Name <span class="text-danger">*</span></label>
                        <input class="form-control" id="fullname" name="fullname" placeholder="Full name" required maxlength="100"
                               value="<?php echo $edit_patient ? htmlspecialchars(html_entity_decode($edit_patient['fullname'], ENT_QUOTES, 'UTF-8')) : ''; ?>">
                    </div>

                    <div class="col-md-3">
                        <label for="dob" class="form-label">Date of Birth <span class="text-danger">*</span></label>
                        <input class="form-control" id="dob" name="dob" type="date" max="<?php echo date('Y-m-d'); ?>" required
                               value="<?php echo $edit_patient ? htmlspecialchars(html_entity_decode($edit_patient['dob'], ENT_QUOTES, 'UTF-8')) : ''; ?>">
                    </div>

                    <div class="col-md-3">
                        <label for="age" class="form-label">Age <span class="text-danger">*</span></label>
                        <input class="form-control" id="age" name="age" type="number" required min="0" max="150" oninput="if(this.value.length > 3) this.value = this.value.slice(0,3);"
                               value="<?php echo $edit_patient ? htmlspecialchars(html_entity_decode($edit_patient['age'], ENT_QUOTES, 'UTF-8')) : ''; ?>">
                    </div>

                    <div class="col-md-3">
                        <label for="gender" class="form-label">Gender <span class="text-danger">*</span></label>
                        <select name="gender" id="gender" class="form-select" required>
                            <option value="">Select Gender</option>
                            <option <?php echo (!$edit_patient || html_entity_decode($edit_patient['gender'], ENT_QUOTES, 'UTF-8')=='Male') ? 'selected':''; ?> value="Male">Male</option>
                            <option <?php echo ($edit_patient && html_entity_decode($edit_patient['gender'], ENT_QUOTES, 'UTF-8')=='Female') ? 'selected':''; ?> value="Female">Female</option>
                            <option <?php echo ($edit_patient && html_entity_decode($edit_patient['gender'], ENT_QUOTES, 'UTF-8')=='Other') ? 'selected':''; ?> value="Other">Other</option>
                        </select>
                    </div>

                    <div class="col-md-3">
                        <label for="marital_status" class="form-label">Marital Status</label>
                        <select name="marital_status" id="marital_status" class="form-select">
                            <option value="">Select Status</option>
                            <option <?php echo (!$edit_patient || html_entity_decode($edit_patient['marital_status'], ENT_QUOTES, 'UTF-8')=='Single') ? 'selected':''; ?> value="Single">Single</option>
                            <option <?php echo ($edit_patient && html_entity_decode($edit_patient['marital_status'], ENT_QUOTES, 'UTF-8')=='Married') ? 'selected':''; ?> value="Married">Married</option>
                            <option <?php echo ($edit_patient && html_entity_decode($edit_patient['marital_status'], ENT_QUOTES, 'UTF-8')=='Divorced') ? 'selected':''; ?> value="Divorced">Divorced</option>
                            <option <?php echo ($edit_patient && html_entity_decode($edit_patient['marital_status'], ENT_QUOTES, 'UTF-8')=='Widowed') ? 'selected':''; ?> value="Widowed">Widowed</option>
                        </select>
                    </div>

                    <div class="col-md-3">
                        <label for="religion" class="form-label">Religion</label>
                        <input class="form-control" id="religion" name="religion" placeholder="Religion" maxlength="50"
                               value="<?php echo $edit_patient ? htmlspecialchars(html_entity_decode($edit_patient['religion'], ENT_QUOTES, 'UTF-8')) : ''; ?>">
                    </div>

                    <div class="col-md-6">
                        <label for="occupation" class="form-label">Occupation</label>
                        <input class="form-control" id="occupation" name="occupation" placeholder="Occupation" maxlength="100"
                               value="<?php echo $edit_patient ? htmlspecialchars(html_entity_decode($edit_patient['occupation'], ENT_QUOTES, 'UTF-8')) : ''; ?>">
                    </div>

                    <!-- Address & Contact -->
                    <h6 class="mt-3">Address & Contact</h6>
                    <div class="col-md-6">
                        <label for="street_address" class="form-label">Street Address</label>
                        <input class="form-control" id="street_address" name="street_address" placeholder="Street Address" maxlength="255"
                               value="<?php echo $edit_patient ? htmlspecialchars(html_entity_decode($edit_patient['street_address'], ENT_QUOTES, 'UTF-8')) : ''; ?>">
                    </div>

                    <div class="col-md-3">
                        <label for="city" class="form-label">City</label>
                        <input class="form-control" id="city" name="city" placeholder="City" maxlength="100"
                               value="<?php echo $edit_patient ? htmlspecialchars(html_entity_decode($edit_patient['city'], ENT_QUOTES, 'UTF-8')) : ''; ?>">
                    </div>

                    <div class="col-md-3">
                        <label for="state" class="form-label">State</label>
                        <input class="form-control" id="state" name="state" placeholder="State" maxlength="50"
                               value="<?php echo $edit_patient ? htmlspecialchars(html_entity_decode($edit_patient['state'], ENT_QUOTES, 'UTF-8')) : ''; ?>">
                    </div>

                    <div class="col-md-3">
                        <label for="zip_code" class="form-label">Zip Code</label>
                        <input class="form-control" id="zip_code" name="zip_code" placeholder="Zip Code" maxlength="10"
                               value="<?php echo $edit_patient ? htmlspecialchars(html_entity_decode($edit_patient['zip_code'], ENT_QUOTES, 'UTF-8')) : ''; ?>">
                    </div>

                    <div class="col-md-3">
                        <label for="primary_contact" class="form-label">Primary Contact</label>
                        <input class="form-control" id="primary_contact" name="primary_contact" placeholder="Primary Contact" maxlength="15"
                               value="<?php echo $edit_patient ? htmlspecialchars(html_entity_decode($edit_patient['primary_contact'], ENT_QUOTES, 'UTF-8')) : ''; ?>">
                    </div>

                    <div class="col-md-3">
                        <label for="secondary_contact" class="form-label">Secondary Contact</label>
                        <input class="form-control" id="secondary_contact" name="secondary_contact" placeholder="Secondary Contact" maxlength="15"
                               value="<?php echo $edit_patient ? htmlspecialchars(html_entity_decode($edit_patient['secondary_contact'], ENT_QUOTES, 'UTF-8')) : ''; ?>">
                    </div>

                    <div class="col-md-3">
                        <label for="email_address" class="form-label">Email Address</label>
                        <input class="form-control" id="email_address" name="email_address" type="email" placeholder="Email" maxlength="100"
                               value="<?php echo $edit_patient ? htmlspecialchars(html_entity_decode($edit_patient['email_address'], ENT_QUOTES, 'UTF-8')) : ''; ?>">
                    </div>

                    <!-- Emergency Contact -->
                    <h6 class="mt-3">Emergency Contact</h6>
                    <div class="col-md-4">
                        <label for="contact_name" class="form-label">Contact Name</label>
                        <input class="form-control" id="contact_name" name="contact_name" placeholder="Emergency Contact Name" maxlength="100"
                               value="<?php echo $edit_patient ? htmlspecialchars(html_entity_decode($edit_patient['contact_name'], ENT_QUOTES, 'UTF-8')) : ''; ?>">
                    </div>

                    <div class="col-md-4">
                        <label for="contact_phone" class="form-label">Contact Phone</label>
                        <input class="form-control" id="contact_phone" name="contact_phone" placeholder="Emergency Contact Phone" maxlength="15"
                               value="<?php echo $edit_patient ? htmlspecialchars(html_entity_decode($edit_patient['contact_phone'], ENT_QUOTES, 'UTF-8')) : ''; ?>">
                    </div>

                    <div class="col-md-4">
                        <label for="relationship" class="form-label">Relationship</label>
                        <input class="form-control" id="relationship" name="relationship" placeholder="Relationship" maxlength="50"
                               value="<?php echo $edit_patient ? htmlspecialchars(html_entity_decode($edit_patient['relationship'], ENT_QUOTES, 'UTF-8')) : ''; ?>">
                    </div>

                    <!-- Insurance -->
                    <h6 class="mt-3">Insurance Information</h6>
                    <div class="col-md-4">
                        <label for="insurance_provider" class="form-label">Insurance Provider</label>
                        <input class="form-control" id="insurance_provider" name="insurance_provider" placeholder="Insurance Provider" maxlength="100"
                               value="<?php echo $edit_patient ? htmlspecialchars(html_entity_decode($edit_patient['insurance_provider'], ENT_QUOTES, 'UTF-8')) : ''; ?>">
                    </div>

                    <div class="col-md-4">
                        <label for="policy_number" class="form-label">Policy Number</label>
                        <input class="form-control" id="policy_number" name="policy_number" placeholder="Policy Number" maxlength="50"
                               value="<?php echo $edit_patient ? htmlspecialchars(html_entity_decode($edit_patient['policy_number'], ENT_QUOTES, 'UTF-8')) : ''; ?>">
                    </div>

                    <div class="col-md-4">
                        <label for="group_number" class="form-label">Group Number</label>
                        <input class="form-control" id="group_number" name="group_number" placeholder="Group Number" maxlength="50"
                               value="<?php echo $edit_patient ? htmlspecialchars(html_entity_decode($edit_patient['group_number'], ENT_QUOTES, 'UTF-8')) : ''; ?>">
                    </div>

                    <div class="col-12 mt-3">
                        <?php if ($edit_patient): ?>
                            <button name="update_patient" class="btn btn-success">
                                <i class="bi bi-check-lg me-2"></i>Update Patient
                            </button>
                            <a href="patients.php" class="btn btn-outline-secondary">Cancel</a>
                        <?php else: ?>
                            <button type="submit" name="add_patient" class="btn btn-primary">
                                <i class="bi bi-person-plus me-2"></i>Add Patient
                            </button>
                        <?php endif; ?>
                    </div>
                </form>
            </div>

            <!-- Patient List -->
            <div class="card p-3">
                <h6>Patient List</h6>
                <!-- Search bar -->
                <div class="mb-3">
                    <div class="input-group rounded" style="max-width: 400px;">
                        <input type="search" id="patientSearch" class="form-control rounded" placeholder="search patient name or patient id" aria-label="Search" aria-describedby="search-addon" />
                        <span class="input-group-text border-0" id="search-addon" style="background: transparent;">
                            <i class="bi bi-search"></i>
                        </span>
                    </div>
                </div>
                <div class="table-responsive">
                    <table class="table table-striped table-hover" id="patientsTable">
                        <thead class="table-dark">
                            <tr>
                                <th>ID</th>
                                <th>Name</th>
                                <th>DOB</th>
                                <th>Age</th>
                                <th>Gender</th>
                                <th>Contact</th>
                                <th>Actions</th>
                            </tr>
                        </thead>
                        <tbody>
                        <?php
                        $res = $conn->query("SELECT * FROM patients ORDER BY fullname");
                        if ($res && $res->num_rows > 0):
                            while ($r = $res->fetch_assoc()):
                                // Fetch additional medical data with prepared statements
                                $medical_data = [];
                                $tables = ['medical_history', 'medications', 'vitals', 'diagnostics', 'treatment_plans', 'lab_results', 'progress_notes', 'physical_assessments'];
                                
                                foreach ($tables as $table) {
                                    $stmt = $conn->prepare("SELECT * FROM `$table` WHERE patient_id = ?");
                                    if ($stmt && $stmt->bind_param("i", $r['id']) && $stmt->execute()) {
                                        $result = $stmt->get_result();
                                        $medical_data[$table] = [];
                                        while ($row = $result->fetch_assoc()) {
                                            $medical_data[$table][] = $row;
                                        }   
                                        $stmt->close();
                                    }
                                }
                        ?>
                            <tr>
                                <td class="patient-id"><?php echo htmlspecialchars($r['id']); ?></td>
                                <td class="patient-name"><?php echo htmlspecialchars($r['fullname']); ?></td>
                                <td><?php echo htmlspecialchars($r['dob'] ?: 'N/A'); ?></td>
                                <td><?php echo htmlspecialchars($r['age'] ?: 'N/A'); ?></td>
                                <td><?php echo htmlspecialchars($r['gender'] ?: 'N/A'); ?></td>
                                <td><?php echo htmlspecialchars($r['primary_contact'] ?: 'N/A'); ?></td>
                                <td>
                                    <div class="btn-group btn-group-sm" role="group">
                                        <a class="btn btn-outline-primary" href="patients.php?edit=<?php echo $r['id']; ?>" title="Edit">
                                            <i class="bi bi-pencil"></i>
                                        </a>
                                        <button class="btn btn-outline-info" data-bs-toggle="modal" data-bs-target="#summaryModal" 
                                                data-patient='<?php echo htmlspecialchars(json_encode(array_merge($r, $medical_data)), ENT_QUOTES); ?>' title="Summary">
                                            <i class="bi bi-eye"></i>
                                        </button>
                                        <a class="btn btn-outline-danger"
                                           href="patients.php?delete=<?php echo $r['id']; ?>&csrf_token=<?php echo $_SESSION['csrf_token']; ?>"
                                           onclick="return confirm('Delete patient and all related records?')" title="Delete">
                                            <i class="bi bi-trash"></i>
                                        </a>
                                        <a class="btn btn-outline-secondary" href="patient_dashboard.php?patient_id=<?php echo $r['id']; ?>" title="Record Vitals">Record</a>
                                    </div>
                                </td>
                            </tr>
                        <?php 
                            endwhile; 
                        else:
                        ?>
                            <tr>
                                <td colspan="7" class="text-center text-muted">No patients found.</td>
                            </tr>
                        <?php endif; ?>
                        </tbody>
                    </table>
                </div>
            </div>
        </div>
    </div>
</div>
</div>

<!-- Summary Modal -->
<div class="modal fade" id="summaryModal" tabindex="-1" aria-labelledby="summaryModalLabel" aria-hidden="true">
    <div class="modal-dialog modal-lg">
        <div class="modal-content">
            <div class="modal-header">
                <h5 class="modal-title" id="summaryModalLabel">
                    <i class="bi bi-person-fill me-2"></i>Patients Demographics
                </h5>
                <button type="button" class="btn-close" data-bs-dismiss="modal" aria-label="Close"></button>
            </div>
            <div class="modal-body">
                <div class="row">
                    <div class="col-12">
                        <div class="card">
                            <div class="card-body">
                                <div id="personalInfo"></div>
                            </div>
                        </div>
                    </div>
                </div>
            </div>
            <div class="modal-footer">
                <button type="button" class="btn btn-secondary" data-bs-dismiss="modal">Close</button>
            </div>
        </div>
    </div>
</div>

<script>
// Auto-dismiss alerts
document.addEventListener('DOMContentLoaded', function() {
    // Auto-dismiss alerts after 5 seconds
    setTimeout(function() {
        const alerts = document.querySelectorAll('.alert');
        alerts.forEach(alert => {
            const bsAlert = new bootstrap.Alert(alert);
            if (bsAlert) bsAlert.close();
        });
    }, 5000);

    // Auto-calculate age from DOB
    document.getElementById('dob').addEventListener('change', function() {
        const dobValue = this.value;
        if (dobValue) {
            const dob = new Date(dobValue);
            const today = new Date();
            let age = today.getFullYear() - dob.getFullYear();
            const monthDiff = today.getMonth() - dob.getMonth();
            if (monthDiff < 0 || (monthDiff === 0 && today.getDate() < dob.getDate())) {
                age--;
            }
            document.getElementById('age').value = age;
        }
    });

    // Form validation
    const form = document.querySelector('form');
    if (form) {
        form.addEventListener('submit', function(e) {
            const fullname = document.getElementById('fullname').value.trim();
            const dob = document.getElementById('dob').value;

            if (fullname.length < 2) {
                e.preventDefault();
                alert('Patient name must be at least 2 characters long.');
                return;
            }

            if (dob && new Date(dob) > new Date()) {
                e.preventDefault();
                alert('Date of birth cannot be in the future.');
                return;
            }
        });
    }
});

// Enhanced summary modal
var summaryModal = document.getElementById('summaryModal');
summaryModal.addEventListener('show.bs.modal', function (event) {
    var button = event.relatedTarget;
    var encodedData = button.getAttribute('data-patient');
    var tempDiv = document.createElement('div');
    tempDiv.innerHTML = encodedData;
    var decodedData = tempDiv.textContent || tempDiv.innerText;
    var patientData = JSON.parse(decodedData);
    // Personal Information
    var personalInfo = `
        <div class="mb-3">
            <h6><i class="bi bi-person me-2"></i>Personal Information</h6>
            <div class="row mb-2">
                <div class="col-sm-4 fw-bold text-primary"><i class="bi bi-hash me-2"></i>ID</div>
                <div class="col-sm-8">${patientData.id}</div>
            </div>
            <div class="row mb-2">
                <div class="col-sm-4 fw-bold text-primary"><i class="bi bi-person me-2"></i>Full Name</div>
                <div class="col-sm-8">${patientData.fullname || 'N/A'}</div>
            </div>
            <div class="row mb-2">
                <div class="col-sm-4 fw-bold text-primary"><i class="bi bi-calendar me-2"></i>Date of Birth</div>
                <div class="col-sm-8">${patientData.dob || 'N/A'}</div>
            </div>
            <div class="row mb-2">
                <div class="col-sm-4 fw-bold text-primary"><i class="bi bi-person-badge me-2"></i>Age</div>
                <div class="col-sm-8">${patientData.age != null ? patientData.age : 'N/A'}</div>
            </div>
            <div class="row mb-2">
                <div class="col-sm-4 fw-bold text-primary"><i class="bi bi-gender-ambiguous me-2"></i>Gender</div>
                <div class="col-sm-8">${patientData.gender || 'N/A'}</div>
            </div>
            <div class="row mb-2">
                <div class="col-sm-4 fw-bold text-primary"><i class="bi bi-heart me-2"></i>Marital Status</div>
                <div class="col-sm-8">${patientData.marital_status || 'N/A'}</div>
            </div>
            <div class="row mb-2">
                <div class="col-sm-4 fw-bold text-primary"><i class="bi bi-star me-2"></i>Religion</div>
                <div class="col-sm-8">${patientData.religion || 'N/A'}</div>
            </div>
            <div class="row mb-2">
                <div class="col-sm-4 fw-bold text-primary"><i class="bi bi-briefcase me-2"></i>Occupation</div>
                <div class="col-sm-8">${patientData.occupation || 'N/A'}</div>
            </div>
        </div>
        <div class="mb-3">
            <h6><i class="bi bi-geo-alt me-2"></i>Address & Contact</h6>
            <div class="row mb-2">
                <div class="col-sm-4 fw-bold text-primary"><i class="bi bi-telephone me-2"></i>Primary Phone</div>
                <div class="col-sm-8">${patientData.primary_contact || 'N/A'}</div>
            </div>
            <div class="row mb-2">
                <div class="col-sm-4 fw-bold text-primary"><i class="bi bi-telephone-fill me-2"></i>Secondary Phone</div>
                <div class="col-sm-8">${patientData.secondary_contact || 'N/A'}</div>
            </div>
            <div class="row mb-2">
                <div class="col-sm-4 fw-bold text-primary"><i class="bi bi-envelope me-2"></i>Email Address</div>
                <div class="col-sm-8">${patientData.email_address || 'N/A'}</div>
            </div>
            <div class="row mb-2">
                <div class="col-sm-4 fw-bold text-primary"><i class="bi bi-geo-alt me-2"></i>Street Address</div>
                <div class="col-sm-8">${patientData.street_address || 'N/A'}</div>
            </div>
            <div class="row mb-2">
                <div class="col-sm-4 fw-bold text-primary"><i class="bi bi-geo-alt-fill me-2"></i>City</div>
                <div class="col-sm-8">${patientData.city || 'N/A'}</div>
            </div>
            <div class="row mb-2">
                <div class="col-sm-4 fw-bold text-primary"><i class="bi bi-geo-alt-fill me-2"></i>State</div>
                <div class="col-sm-8">${patientData.state || 'N/A'}</div>
            </div>
            <div class="row mb-2">
                <div class="col-sm-4 fw-bold text-primary"><i class="bi bi-geo-alt-fill me-2"></i>Zip Code</div>
                <div class="col-sm-8">${patientData.zip_code || 'N/A'}</div>
            </div>
        </div>
        <div class="mb-3">
            <h6><i class="bi bi-person-plus me-2"></i>Emergency Contact</h6>
            <div class="row mb-2">
                <div class="col-sm-4 fw-bold text-primary"><i class="bi bi-person-plus me-2"></i>Contact Name</div>
                <div class="col-sm-8">${patientData.contact_name || 'N/A'}</div>
            </div>
            <div class="row mb-2">
                <div class="col-sm-4 fw-bold text-primary"><i class="bi bi-telephone-plus me-2"></i>Contact Phone</div>
                <div class="col-sm-8">${patientData.contact_phone || 'N/A'}</div>
            </div>
            <div class="row mb-2">
                <div class="col-sm-4 fw-bold text-primary"><i class="bi bi-people me-2"></i>Relationship</div>
                <div class="col-sm-8">${patientData.relationship || 'N/A'}</div>
            </div>
        </div>
        <div class="mb-3">
            <h6><i class="bi bi-shield-check me-2"></i>Insurance Information</h6>
            <div class="row mb-2">
                <div class="col-sm-4 fw-bold text-primary"><i class="bi bi-shield-check me-2"></i>Insurance Provider</div>
                <div class="col-sm-8">${patientData.insurance_provider || 'N/A'}</div>
            </div>
            <div class="row mb-2">
                <div class="col-sm-4 fw-bold text-primary"><i class="bi bi-card-text me-2"></i>Policy Number</div>
                <div class="col-sm-8">${patientData.policy_number || 'N/A'}</div>
            </div>
            <div class="row mb-2">
                <div class="col-sm-4 fw-bold text-primary"><i class="bi bi-card-text me-2"></i>Group Number</div>
                <div class="col-sm-8">${patientData.group_number || 'N/A'}</div>
            </div>
        </div>
    `;
    document.getElementById('personalInfo').innerHTML = personalInfo;
});

// Live search filter for patient names and IDs
document.addEventListener('DOMContentLoaded', function() {
    const searchInput = document.getElementById('patientSearch');
    const table = document.getElementById('patientsTable');
    const rows = table.getElementsByTagName('tbody')[0].getElementsByTagName('tr');

    searchInput.addEventListener('input', function() {
        const filter = this.value.toLowerCase();

        Array.from(rows).forEach(row => {
            const nameCell = row.querySelector('.patient-name');
            const idCell = row.querySelector('.patient-id');
            let showRow = false;

            if (nameCell) {
                const nameText = nameCell.textContent.toLowerCase();
                if (nameText.indexOf(filter) > -1) {
                    showRow = true;
                }
            }

            if (idCell) {
                const idText = idCell.textContent.toLowerCase();
                if (idText.indexOf(filter) > -1) {
                    showRow = true;
                }
            }

            row.style.display = showRow ? '' : 'none';
        });
    });
});
</script>

<?php include "footer.php"; ?>
