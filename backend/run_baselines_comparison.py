import os, sys
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__))))
import pandas as pd
import numpy as np
from sklearn.model_selection import train_test_split, StratifiedKFold, cross_val_score
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.linear_model import LogisticRegression
from sklearn.naive_bayes import MultinomialNB
from sklearn.svm import LinearSVC
from sklearn.metrics import accuracy_score, precision_recall_fscore_support, confusion_matrix, classification_report
from sklearn.pipeline import Pipeline
from app.preprocessing import normalize_for_model

df = pd.read_csv(os.path.join(os.path.dirname(__file__), 'data', 'training_data.csv'))
cleaned_texts = [normalize_for_model(t) for t in df['text']]

benchmark = [
    ('An employee received an invoice notification with an HTML attachment that redirected to a credential harvesting site mimicking Microsoft 365.', 'Phishing', 'Low'),
    ('Threat actors sent spear-phishing messages with malicious QR codes (quishing) to executive assistants to bypass email gateways.', 'Phishing', 'Medium'),
    ('Multiple corporate mailboxes were flooded with deceptive meeting invitations containing links to a malicious SharePoint login portal.', 'Phishing', 'Medium'),
    ('Cisco Talos detected a new loader executing obfuscated PowerShell scripts that dropped a banking trojan into AppData.', 'Malware', 'Medium'),
    ('EDR detected unauthorized process injection into svchost.exe communicating with an external Russian IP address.', 'Malware', 'High'),
    ('An unknown payload was dropped via macro-enabled Excel sheet and established persistence via scheduled tasks.', 'Malware', 'Medium'),
    ('BlackCat threat actors encrypted critical hypervisor nodes across the organization, deploying double extortion tactics with file dumps.', 'Ransomware', 'Critical'),
    ('File servers in the hospital went offline after all healthcare records were encrypted with a .locked extension and a ransom notice.', 'Ransomware', 'Critical'),
    ('Akira group compromised VPN credentials, deleted volume shadow copies, and encrypted backup SAN storage arrays.', 'Ransomware', 'Critical'),
    ('The customer portal was knocked offline by a 400 Gbps SYN flood and DNS amplification attack targeting edge routers.', 'DDoS', 'High'),
    ('Volumetric NTP reflection attack saturated the perimeter bandwidth, causing a 4-hour outage for retail e-commerce servers.', 'DDoS', 'Medium'),
    ('A botnet launched an HTTP/2 Rapid Reset distributed denial of service attack overwhelming backend microservices.', 'DDoS', 'High'),
    ('A departing software engineer cloned private company repositories and transferred intellectual property to a personal USB device.', 'Insider Threat', 'High'),
    ('System administrator abused privileged root access to snoop on executive Slack messages and download confidential compensation records.', 'Insider Threat', 'Medium'),
    ('A disgruntled IT contractor created rogue backdoor admin accounts before their contract termination date.', 'Insider Threat', 'High'),
    ('An unprotected Elasticsearch cluster exposed 2.4 million customer records including hashed passwords and email addresses on the open web.', 'Data Breach', 'Critical'),
    ('SQL injection vulnerability in the legacy web storefront allowed threat actors to dump the entire customer credit card table.', 'Data Breach', 'Critical'),
    ('An API misconfiguration permitted unauthenticated enumeration of patient profiles and medical records via object-level authorization flaw.', 'Data Breach', 'High'),
]
bench_texts = [normalize_for_model(s[0]) for s in benchmark]
bench_type = [s[1] for s in benchmark]
bench_sev = [s[2] for s in benchmark]

models = {
    'Logistic Regression': lambda: LogisticRegression(max_iter=2000, C=2.0, random_state=42),
    'Multinomial Naive Bayes': lambda: MultinomialNB(alpha=1.0),
    'Linear SVM': lambda: LinearSVC(C=1.0, random_state=42, max_iter=2000)
}

for task_name, target_col, b_target in [('Incident Classification', 'incident_type', bench_type), ('Severity Prediction', 'severity', bench_sev)]:
    print('=' * 70)
    print('TASK:', task_name)
    print('=' * 70)
    labels = df[target_col].tolist()
    X_train, X_test, y_train, y_test = train_test_split(
        cleaned_texts, labels, test_size=0.20, random_state=42, stratify=labels
    )
    cv = StratifiedKFold(n_splits=5, shuffle=True, random_state=42)
    
    for m_name, m_factory in models.items():
        print(f'\n--- Model: {m_name} ---')
        pipe = Pipeline([
            ('tfidf', TfidfVectorizer(max_features=3000, ngram_range=(1, 2), min_df=1)),
            ('clf', m_factory())
        ])
        pipe.fit(X_train, y_train)
        
        # Holdout
        y_test_pred = pipe.predict(X_test)
        holdout_acc = accuracy_score(y_test, y_test_pred)
        p_m, r_m, f1_m, _ = precision_recall_fscore_support(y_test, y_test_pred, average='macro', zero_division=0)
        
        # 5-fold CV
        cv_scores = cross_val_score(pipe, cleaned_texts, labels, cv=cv, scoring='accuracy')
        
        # Benchmark
        b_pred = pipe.predict(bench_texts)
        b_acc = accuracy_score(b_target, b_pred)
        bp_m, br_m, bf1_m, _ = precision_recall_fscore_support(b_target, b_pred, average='macro', zero_division=0)
        correct_cnt = sum(np.array(b_target) == np.array(b_pred))
        
        print(f'Holdout Acc: {holdout_acc*100:.2f}% | Holdout Macro-F1: {f1_m:.4f}')
        print(f'5-Fold CV Mean Acc: {cv_scores.mean()*100:.2f}% (+/- {cv_scores.std()*100:.2f}%)')
        print(f'Benchmark Acc: {b_acc*100:.2f}% ({correct_cnt}/{len(benchmark)}) | Benchmark Macro-F1: {bf1_m:.4f} | Macro-Precision: {bp_m:.4f} | Macro-Recall: {br_m:.4f}')
        print('Benchmark Per-Class Report:')
        print(classification_report(b_target, b_pred, zero_division=0))
        print('Benchmark Confusion Matrix:')
        print(f'Classes: {list(pipe.classes_)}')
        print(confusion_matrix(b_target, b_pred, labels=pipe.classes_))
