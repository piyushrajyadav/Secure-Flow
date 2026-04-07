from setuptools import setup, find_packages

with open("README.md", "r", encoding="utf-8") as fh:
    long_description = fh.read()

setup(
    name="secureflow-ai",  # 'secureflow-ai' is unique for PyPI
    version="0.1.0",
    author="Your Name",  # You can change this later
    author_email="your.email@example.com",
    description="Security middleware for Multi-Agent AI Systems (LangGraph/LangChain).",
    long_description=long_description,
    long_description_content_type="text/markdown",
    url="https://github.com/yourusername/secureflow",
    packages=find_packages(include=["secureflow", "secureflow.*"]),
    classifiers=[
        "Development Status :: 4 - Beta",
        "Intended Audience :: Developers",
        "Programming Language :: Python :: 3",
        "License :: OSI Approved :: MIT License",
        "Operating System :: OS Independent",
        "Topic :: Security",
        "Topic :: Scientific/Engineering :: Artificial Intelligence",
    ],
    python_requires=">=3.9",
    install_requires=[
        "langchain>=0.3.0",
        "langchain-core>=0.3.0",
        "langgraph>=0.2.0",
        "colorama>=0.4.6"
    ],
)
