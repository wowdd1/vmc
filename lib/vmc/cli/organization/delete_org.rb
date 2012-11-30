require "vmc/cli/organization/base"

module VMC::Organization
  class DeleteOrg < Base
    desc "Delete an organization"
    group :organizations
    input(:organization, :aliases => ["--org", "-o"],
          :argument => :optional,
          :from_given => by_name("organization"),
          :desc => "Organization to delete") { |orgs|
      ask "Which organization?", :choices => orgs,
          :display => proc(&:name)
    }
    input(:really, :type => :boolean, :forget => true,
          :default => proc { force? || interact }) { |org|
      ask("Really delete #{c(org.name, :name)}?", :default => false)
    }
    input(:recursive, :alias => "-r", :type => :boolean, :forget => true) {
      ask "Delete #{c("EVERYTHING", :bad)}?", :default => false
    }
    input :warn, :type => :boolean, :default => true,
          :desc => "Show warning if it was the last org"
    def delete_org
      orgs = client.organizations
      fail "No organizations." if orgs.empty?

      org = input[:organization, orgs]
      return unless input[:really, org]

      spaces = org.spaces
      unless spaces.empty?
        unless force?
          line "This organization is not empty!"
          line
          line "spaces: #{name_list(spaces)}"
          line

          return unless input[:recursive]
        end

        spaces.each do |s|
          invoke :delete_space, :space => s, :really => true,
                 :recursive => true, :warn => false
        end
      end

      is_current = org == client.current_organization

      with_progress("Deleting organization #{c(org.name, :name)}") do
        org.delete!
      end

      if orgs.size == 1
        return unless input[:warn]

        line
        line c("There are no longer any organizations.", :warning)
        line "You may want to create one with #{c("create-org", :good)}."
      elsif is_current
        invalidate_target
        invoke :target
      end
    end
  end
end