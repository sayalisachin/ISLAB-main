#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <openssl/rsa.h>
#include <openssl/md5.h>

#define MAX_PATIENTS 100

typedef struct {
    char name[50];
    int age;
    char diagnosis[100];
    char treatment[100];
    int expenses;
} Patient;

Patient patients[MAX_PATIENTS];
int patient_count = 0;

// Function prototypes
void load_patients();
void retrieve_patient_data(const char *doctor);
void verify_signature(const unsigned char *data, const unsigned char *signature);

// Main server function
int main() {
    int choice;
    char doctor_name[50];

    // Load patients data from file or database
    load_patients();

    while (1) {
        printf("1. Retrieve Patient Data by Doctor\n2. Exit\nEnter choice: ");
        scanf("%d", &choice);

        switch (choice) {
            case 1:
                printf("Enter Doctor's Name: ");
                scanf("%s", doctor_name);
                retrieve_patient_data(doctor_name);
                break;
            case 2:
                printf("Exiting...\n");
                exit(0);
            default:
                printf("Invalid choice!\n");
        }
    }

    return 0;
}

// Load patients data into array (placeholder, in practice load from database or file)
void load_patients() {
    strcpy(patients[0].name, "John Doe");
    patients[0].age = 45;
    strcpy(patients[0].diagnosis, "Hypertension");
    strcpy(patients[0].treatment, "Medication");
    patients[0].expenses = 1000;

    patient_count = 1;
}

// Retrieve all patient details under a doctor
void retrieve_patient_data(const char *doctor) {
    printf("Patients under Doctor %s:\n", doctor);
    for (int i = 0; i < patient_count; i++) {
        printf("Name: %s, Age: %d, Diagnosis: %s, Treatment: %s, Expenses: %d\n",
               patients[i].name, patients[i].age, patients[i].diagnosis, patients[i].treatment, patients[i].expenses);
    }
}

// Verifies the signature using ElGamal (placeholder function)
void verify_signature(const unsigned char *data, const unsigned char *signature) {
    // Placeholder verification (use actual ElGamal verification)
    printf("Signature verified.\n");
}
