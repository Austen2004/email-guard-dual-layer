"""
Offline & Standalone ML Model Training Script for DualShield.
Trains, evaluates, and serializes the Machine Learning spam classifier.
Generates full precision, recall, F1, and accuracy benchmark metrics.
"""

from layer2_ml import MLEmailClassifier

def main():
    print("=" * 60)
    print(" DualShield Email Guard - Machine Learning Model Trainer")
    print("=" * 60)
    print("[1/3] Initializing ML classifier...")
    classifier = MLEmailClassifier()

    print("[2/3] Training pipeline on dataset...")
    results = classifier.train_and_save()

    print(f"\n[3/3] Training Complete! Model saved successfully.")
    print(f"Total Samples Trained: {results['samples_count']}")
    print(f"Overall Accuracy:      {results['accuracy'] * 100:.2f}%\n")

    report = results["report"]
    print("-" * 60)
    print(f"{'Class':<12} | {'Precision':<10} | {'Recall':<10} | {'F1-Score':<10} | {'Support':<8}")
    print("-" * 60)
    print(f"{'HAM (Clean)':<12} | {report['0']['precision']:<10.2f} | {report['0']['recall']:<10.2f} | {report['0']['f1-score']:<10.2f} | {report['0']['support']:<8}")
    print(f"{'SPAM (Threat)':<12} | {report['1']['precision']:<10.2f} | {report['1']['recall']:<10.2f} | {report['1']['f1-score']:<10.2f} | {report['1']['support']:<8}")
    print("-" * 60)

if __name__ == "__main__":
    main()
