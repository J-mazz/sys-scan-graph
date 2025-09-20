# Dataset Setup Instructions

## Problem
Having to upload `massive_datasets.tar.gz` manually to Colab every time is frustrating and time-consuming.

## Solution: Automatic Downloading

### Step 1: Host Your Dataset
Upload your `massive_datasets.tar.gz` to one of these services:
- **GitHub Releases**: Create a release and upload the file
- **Google Drive**: Upload and get shareable link
- **Your own CDN/server**: Host it somewhere accessible

### Step 2: Update Download URLs
Edit `agent/ml_pipeline/download_dataset.py` and update the `download_urls` list:

```python
download_urls = [
    "https://github.com/YOUR_USERNAME/YOUR_REPO/releases/download/v1.0/massive_datasets.tar.gz",
    "https://drive.google.com/uc?export=download&id=YOUR_FILE_ID",
    "https://your-cdn.com/massive_datasets.tar.gz",
]
```

### Step 3: For Google Drive Links
Convert shareable Google Drive links to direct download links:
- Original: `https://drive.google.com/file/d/FILE_ID/view?usp=sharing`
- Download: `https://drive.google.com/uc?export=download&id=FILE_ID`

### Step 4: Test the Download
Run the download script locally first:
```bash
cd agent/ml_pipeline
python download_dataset.py
```

### Step 5: Use in Colab
The updated Colab script will now automatically download the dataset instead of requiring manual upload.

## Alternative: Smaller Test Dataset

For development/testing, create a smaller dataset:
```bash
# Create a sample dataset with just a few files
mkdir -p test_data
# Copy a subset of your data here
# Then tar it: tar -czf test_datasets.tar.gz test_data/
```

## Benefits
- ✅ No more manual uploads
- ✅ Faster Colab startup
- ✅ Consistent dataset across runs
- ✅ Version control for dataset changes</content>
<parameter name="filePath">/home/joseph-mazzini/sys-scan-graph/DATASET_SETUP.md