package services

import (
	"encoding/json"
	"fmt"
	"net/http"
)

type CaseResponse struct {
	ID       int64  `json:"id,string"` // Handles ID from Node.js (string "5")
	PublicID string `json:"public_id"`
	Title    string `json:"title"`
}

type CaseUserResponse struct {
	PublicID string `json:"public_id"`
	Name     string `json:"name"`
	Email    string `json:"email"`
}

// ValidateCase calls the case service to verify the case exists.
// Returns the case internal ID and error.
func ValidateCase(casePublicID string, token string) (*CaseResponse, error) {

	url := fmt.Sprintf("http://localhost:4000/cases/%s", casePublicID)

	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		return nil, err
	}

	req.Header.Set("Authorization", "Bearer "+token)

	client := &http.Client{}
	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != 200 {
		return nil, fmt.Errorf("case not found, status: %d", resp.StatusCode)
	}

	var caseData CaseResponse
	if err := json.NewDecoder(resp.Body).Decode(&caseData); err != nil {
		return nil, fmt.Errorf("failed to decode case response: %w", err)
	}

	return &caseData, nil
}

// CheckUserCaseAccess verifies that a user (by public_id) is assigned to a case.
// It calls the case service's case_users endpoint.
func CheckUserCaseAccess(casePublicID string, userPublicID string, token string) (bool, error) {

	url := fmt.Sprintf("http://localhost:4000/cases/%s/users", casePublicID)

	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		return false, err
	}

	req.Header.Set("Authorization", "Bearer "+token)

	client := &http.Client{}
	resp, err := client.Do(req)
	if err != nil {
		return false, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != 200 {
		return false, fmt.Errorf("failed to fetch case users, status: %d", resp.StatusCode)
	}

	var users []CaseUserResponse
	if err := json.NewDecoder(resp.Body).Decode(&users); err != nil {
		return false, fmt.Errorf("failed to decode case users: %w", err)
	}

	for _, u := range users {
		if u.PublicID == userPublicID {
			return true, nil
		}
	}

	return false, nil
}