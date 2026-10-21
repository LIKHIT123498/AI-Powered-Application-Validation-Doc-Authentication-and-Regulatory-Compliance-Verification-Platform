# 🏛️ AI-Powered Application Validation & Compliance Verification

![FastAPI](https://img.shields.io/badge/FastAPI-005571?style=flat&logo=fastapi)
![React](https://img.shields.io/badge/React-20232A?style=flat&logo=react&logoColor=61DAFB)
![PostgreSQL](https://img.shields.io/badge/PostgreSQL-316192?style=flat&logo=postgresql&logoColor=white)
![Google Gemini](https://img.shields.io/badge/Google_Gemini-8E75B2?style=flat&logo=google&logoColor=white)

## 📌 Project Overview
This platform is an AI-enabled decision-support system designed to automate the preliminary validation of institutional applications, authenticate supporting documents, and assist in checking regulatory compliance at the earliest stage to reduce administrative bottlenecks.

## ✨ Key Features
*   **Intelligent Document Validation:** OCR and data extraction using PyMuPDF to parse institutional records and identify missing, incomplete, or expired documents.
*   **AI Anomaly & Forgery Detection:** Cross-references data and utilizes Google Gemini (via structured JSON schemas) to detect suspicious alterations, inconsistent metadata, and document duplication.
*   **Automated Authority Verification:** Integrated workflow to verify documents via APIs, digital repositories, and QR codes from original issuing authorities.
*   **Infrastructure Compliance Assistance:** Rule-based and computer-vision-assisted checking of infrastructure evidence (floor plans, photos) against standard regulatory compliance handbooks.
*   **Evidence-Linked Dashboard:** A centralized, Role-Based Access Control (RBAC) portal for reviewers to check automated flags and full audit trails before making regulatory decisions.

## 🛠️ Technology Stack
*   **Backend:** Python, FastAPI (for async document processing)
*   **Frontend:** React.js, TypeScript, Tailwind CSS
*   **AI & LLM:** Google Gemini 2.5 Flash, TensorFlow/OpenCV
*   **Document Processing:** PyMuPDF (fitz), pypdf
*   **Database:** PostgreSQL (with SQLAlchemy/SQLModel)
*   **Deployment Architecture:** Render (Backend), Vercel (Frontend), Neon/Supabase (Database)

## 🚀 Getting Started

### Prerequisites
*   Python 3.10+
*   Node.js 18+
*   PostgreSQL
*   Google Gemini API Key

### Installation (Local Development)
1. **Clone the repository:**
   ```bash
   git clone [https://github.com/yourusername/compliance-validation-platform.git](https://github.com/yourusername/compliance-validation-platform.git)
   cd compliance-validation-platform
