class IamShrink < Formula
  desc "Local-to-Least-Privilege AWS IAM Policy Generator"
  homepage "https://github.com/smford/iam-shrink"
  url "https://github.com/smford/iam-shrink/archive/refs/tags/v0.5.0.tar.gz"
  license "MIT"

  depends_on "go" => :build

  def install
    system "go", "build", *std_go_args(ldflags: "-s -w -X main.version=#{version}"), "./cmd/iam-shrink"
  end

  test do
    assert_match "iam-shrink version", shell_output("#{bin}/iam-shrink version")
  end
end
